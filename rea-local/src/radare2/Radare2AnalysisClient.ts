import { randomUUID } from "node:crypto";
import { stat } from "node:fs/promises";
import { basename } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
} from "../application/AnalysisProvider.js";
import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
import { createProviderTargetSnapshot } from "../process/ProviderTargetSnapshot.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import type { Radare2Dialect } from "./Radare2Dialect.js";
import {
  RADARE2_LIMITATIONS,
  RADARE2_OPERATIONS,
  RADARE2_PROVIDER_IDENTITY,
  RIZIN_LIMITATIONS,
  type Radare2Operation,
} from "./Radare2Identity.js";
import type { Radare2AnalysisLevel } from "../config/radare2Settings.js";
import { Radare2OperationRunner } from "./Radare2Operations.js";
import {
  Radare2Pipe,
  Radare2PipeFailure,
  RADARE2_MAX_REPLY_BYTES,
  type Radare2Launcher,
} from "./Radare2Pipe.js";
import {
  parseSessionVersion,
  radare2InfoSchema,
  radare2Reply,
} from "./Radare2Values.js";

/** Session settings resolved by the provider before any process starts. */
export interface Radare2ClientOptions {
  /** Resolved real path of the caller-supplied radare2 or Rizin executable. */
  readonly executable: string;
  /** Command dialect of that executable, from its `-v` banner. */
  readonly dialect: Radare2Dialect;
  /** Engine version committed by the analysis profile. */
  readonly engineVersion: string;
  readonly analysisLevel: Radare2AnalysisLevel;
  readonly analysisTimeoutMs: number;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly launcher?: Radare2Launcher;
  /** Parent directory for private runtime roots; defaults to the OS temp dir. */
  readonly runtimeParent?: string;
}

interface ActiveSession {
  readonly root: PrivateRuntimeRoot;
  readonly pipe: Radare2Pipe;
  readonly runner: Radare2OperationRunner;
}

/** Resources whose cleanup failed and must be retried before close succeeds. */
interface RetainedCleanup {
  readonly root: PrivateRuntimeRoot;
  readonly pipe: Radare2Pipe | undefined;
  reason: string;
}

/** radare2 session bound to exactly one admitted target and its private copy. */
export class Radare2AnalysisClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #session: ActiveSession | undefined;
  #retained: RetainedCleanup[] = [];
  #closed = false;

  constructor(
    private readonly target: BinaryTarget,
    private readonly options: Radare2ClientOptions,
    private readonly profile?: AnalysisProfileCommitment,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: { readonly signal?: AbortSignal },
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options?.signal),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ) {
    if (this.#closed)
      return err(
        new AnalysisProtocolError(
          "radare2 provider session is closed; reopen the target.",
        ),
      );
    if (signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    if (!isRadare2Operation(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          RADARE2_PROVIDER_IDENTITY.id,
          operation,
          "The radare2 adapter has no normalized route for this operation.",
        ),
      );
    const contract = TOOL_CONTRACTS.find(({ name }) => name === operation);
    const parsed = contract?.inputSchema.safeParse(parameters);
    if (parsed?.success !== true)
      return err(new AnalysisInputError(operation, { cause: parsed?.error }));
    const input = jsonValueSchema.parse(parsed.data) as Readonly<
      Record<string, JsonValue>
    >;
    try {
      const session = await this.#start(operation, signal);
      const outcome = await session.runner.execute(operation, input, signal);
      return ok(
        createAnalysisExecution(outcome.result, RADARE2_PROVIDER_IDENTITY, {
          rawResult: {
            engine: this.options.dialect.engine,
            engine_version: this.options.engineVersion,
            analysis_level: this.options.analysisLevel,
            commands: [...outcome.commands],
          },
          limitations:
            this.options.dialect.engine === "rizin"
              ? RIZIN_LIMITATIONS
              : RADARE2_LIMITATIONS,
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...(outcome.address === undefined
              ? []
              : [{ kind: "address" as const, address: outcome.address }]),
          ],
          subject: {
            path: this.target.path,
            sha256: this.target.sha256,
            format: this.target.format,
            ...(this.target.architecture === undefined
              ? {}
              : { architecture: this.target.architecture }),
          },
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    } catch (cause: unknown) {
      return err(await this.#failure(operation, cause, signal));
    }
  }

  async #start(
    operation: string,
    signal?: AbortSignal,
  ): Promise<ActiveSession> {
    if (this.#session !== undefined) return this.#session;
    const root = await PrivateRuntimeRoot.create({
      prefix: "rea-radare2-",
      ...(this.options.runtimeParent === undefined
        ? {}
        : { parent: this.options.runtimeParent }),
    });
    const deadline = new ProviderStartupDeadline(
      this.options.analysisTimeoutMs,
      signal,
    );
    let pipe: Radare2Pipe | undefined;
    try {
      const snapshot = await createProviderTargetSnapshot(
        this.target.path,
        root.path,
        this.target.sha256,
        { providerName: "radare2", signal: deadline.signal },
      );
      const fileName = basename(snapshot.path);
      const { dialect } = this.options;
      pipe = await Radare2Pipe.start(
        {
          executable: this.options.executable,
          arguments: [...dialect.processArguments, fileName],
          cwd: root.path,
          runId: randomUUID(),
          hostEnvironment: { ...this.options.environment },
          ...(this.options.launcher === undefined
            ? {}
            : { launcher: this.options.launcher }),
        },
        deadline.signal,
      );
      const version = parseSessionVersion(
        dialect,
        await pipe.command(dialect.versionCommand, deadline.signal),
      );
      if (version !== this.options.engineVersion)
        throw new AnalysisProtocolError(
          `The ${dialect.engine} executable reported ${version ?? "an unrecognized version"} but the analysis profile committed ${this.options.engineVersion}; reopen the target to resolve a new profile.`,
        );
      const info = radare2Reply(
        operation,
        "ij",
        await pipe.command("ij", deadline.signal),
        radare2InfoSchema,
      );
      const snapshotSize = (await stat(snapshot.path)).size;
      if (info.core.file !== fileName || info.core.size !== snapshotSize)
        throw new AnalysisProtocolError(
          "radare2 did not open the admitted private target copy.",
        );
      // Analysis replies with no output; its completion is the reply NUL.
      await pipe.command(this.options.analysisLevel, deadline.signal);
      const activePipe = pipe;
      const session: ActiveSession = {
        root,
        pipe: activePipe,
        runner: new Radare2OperationRunner(
          {
            run: (command, commandSignal) =>
              activePipe.command(command, commandSignal),
          },
          {
            documentName: basename(this.target.path),
            sourcePath: this.target.path,
            snapshotPath: snapshot.path,
            dialect,
            fileDescriptor: info.core.fd,
            baseAddress: info.bin.baddr,
          },
        ),
      };
      this.#session = session;
      return session;
    } catch (cause: unknown) {
      await this.#release(root, pipe);
      throw cause;
    } finally {
      deadline.dispose();
    }
  }

  async #failure(
    operation: string,
    cause: unknown,
    signal?: AbortSignal,
  ): Promise<AnalysisError> {
    if (cause instanceof Radare2PipeFailure) {
      const session = this.#session;
      this.#session = undefined;
      if (session !== undefined)
        await this.#release(session.root, session.pipe);
      if (cause.reason === "cancelled")
        return new AnalysisCancelledError(operation, { cause });
      if (cause.reason === "timeout")
        return new AnalysisTimeoutError(
          operation,
          this.options.analysisTimeoutMs,
          { cause },
        );
      if (cause.reason === "output-limit")
        return new AnalysisResourceConstraintError(
          operation,
          "transport",
          cause.message,
          { max_reply_bytes: RADARE2_MAX_REPLY_BYTES, command: cause.command },
          { cause },
        );
      return new ProviderAdapterError(RADARE2_PROVIDER_IDENTITY.id, operation, {
        cause,
        diagnostics: {
          reason: cause.message,
          command: cause.command,
          stderr: cause.stderr.slice(-4096),
          recovery:
            "The next operation starts a fresh radare2 process. Check REA_RADARE2_PATH and the retained stderr if the failure repeats.",
        },
      });
    }
    if (signal?.aborted === true)
      return new AnalysisCancelledError(operation, { cause });
    if (cause instanceof AnalysisError) return cause;
    return new ProviderAdapterError(RADARE2_PROVIDER_IDENTITY.id, operation, {
      cause,
      diagnostics: {
        reason: cause instanceof Error ? cause.message : "Unknown failure",
      },
    });
  }

  /** Stop the process and remove the private root, retaining what failed. */
  async #release(
    root: PrivateRuntimeRoot,
    pipe: Radare2Pipe | undefined,
  ): Promise<void> {
    const stopped = await pipe?.stop();
    if (stopped?.status === "incomplete") {
      this.#retained.push({ root, pipe, reason: stopped.reason });
      return;
    }
    try {
      await root.close();
    } catch (cause: unknown) {
      this.#retained.push({
        root,
        pipe: undefined,
        reason:
          cause instanceof Error
            ? cause.message
            : "private runtime root removal failed",
      });
    }
  }

  async close(): Promise<Result<null, AnalysisError>> {
    await this.#tail;
    this.#closed = true;
    const session = this.#session;
    this.#session = undefined;
    if (session !== undefined) await this.#release(session.root, session.pipe);
    const retained = this.#retained.splice(0);
    for (const item of retained) await this.#release(item.root, item.pipe);
    if (this.#retained.length === 0) return ok(null);
    return err(
      new ProviderCleanupError(
        RADARE2_PROVIDER_IDENTITY.id,
        this.#retained.map(({ root }) => root.path),
        { reasons: this.#retained.map(({ reason }) => reason) },
      ),
    );
  }
}

const isRadare2Operation = (
  operation: AnalysisOperation,
): operation is Radare2Operation =>
  (RADARE2_OPERATIONS as readonly string[]).includes(operation);
