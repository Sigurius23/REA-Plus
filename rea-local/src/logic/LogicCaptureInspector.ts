import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { LogicCapturePort } from "../application/logic/LogicCapturePort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  logicCaptureSchema,
  type InspectLogicCaptureInput,
  type LogicCapture,
} from "../domain/logic/logicCapture.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { OwnedCommandFailure } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import {
  byteStream,
  decoderStack,
  parseAnnotations,
  parseDecoderClasses,
  runSigrok,
  SIGROK_LIMITS,
  SigrokDecodeRejected,
  sigrokProfile,
  SigrokUnavailable,
} from "./SigrokCli.js";
import {
  analogStatistics,
  channelStatistics,
  MAX_SESSION_SAMPLE_BYTES,
  readSigrokSession,
  SigrokSessionError,
  type SigrokSession,
} from "./SigrokSession.js";

type Launcher = Parameters<typeof runSigrok>[2]["launcher"];
type Runtime = Pick<PrivateRuntimeRoot, "path" | "close">;

const OPERATION = "inspect_logic_capture";
const SNAPSHOT = "capture.sr";

export const LOGIC_CAPTURE_PROVIDER_IDENTITY = {
  id: "sigrok-logic-capture",
  name: "REA+ sigrok session reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Channel statistics come from every recorded sample; estimated_bit_rate averages the shortest pulses, so glitches shorter than a bit skew it.",
  "Protocol annotations are sigrok decoders' interpretation with the caller's channel mapping and options; a wrong baud rate or mode yields plausible but wrong data.",
  "sigrok-cli and its Python decoders are trusted caller-supplied programs; their version banner and executable SHA-256 identify them, not publisher authenticity.",
  "Only the session's first device is read. Saleae and other formats need converting to a sigrok session first (for example with sigrok-cli -I csv).",
];

class LogicInputRejected extends Error {
  constructor(
    readonly field: "decoders" | "annotations",
    message: string,
  ) {
    super(message);
  }
}

const inputError = (field: string, message: string, cause: unknown) =>
  new AnalysisInputError(OPERATION, { cause }, [
    { path: [field], reason: "invalid_value", message },
  ]);

/** Lifecycle failures of the owned sigrok-cli process. */
const processFailure = (cause: OwnedCommandFailure): AnalysisError =>
  cause.reason === "cancelled"
    ? new AnalysisCancelledError(OPERATION, { cause })
    : cause.reason === "timeout"
      ? new AnalysisTimeoutError(OPERATION, SIGROK_LIMITS.timeoutMs, { cause })
      : new AnalysisOutputError(OPERATION, cause.message, { cause });

const toolFailure = (cause: unknown, reason: string): AnalysisError | null => {
  if (cause instanceof OwnedCommandFailure) return processFailure(cause);
  if (cause instanceof SigrokUnavailable)
    return new AnalysisCapabilityUnavailableError(
      LOGIC_CAPTURE_PROVIDER_IDENTITY.id,
      OPERATION,
      reason,
      {
        cause,
        userMessage: `${reason} Install sigrok-cli 0.7 with its protocol decoders and set absolute REA_SIGROK_CLI; REA+ does not install tools.`,
      },
    );
  if (cause instanceof LogicInputRejected)
    return inputError(cause.field, reason, cause);
  if (cause instanceof SigrokDecodeRejected)
    return inputError(
      "decoders",
      `sigrok-cli rejected the stack: ${reason}`,
      cause,
    );
  return null;
};

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  const tool = toolFailure(cause, reason);
  if (tool !== null) return tool;
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  return inputError(
    "path",
    cause instanceof SigrokSessionError ||
      cause instanceof ArtifactReaderFailure
      ? `Not a readable sigrok session: ${reason}`
      : reason,
    cause,
  );
};

/** Decoder channels must name capture channels sigrok-cli can address. */
const checkStack = (
  decoders: NonNullable<InspectLogicCaptureInput["decoders"]>,
  session: SigrokSession,
): void => {
  const names = new Set(session.logicChannels.map(({ name }) => name));
  decoders.forEach(({ id, channels }, position) => {
    const mapped = Object.values(channels);
    if (position > 0 && mapped.length > 0)
      throw new LogicInputRejected(
        "decoders",
        `Only the bottom decoder takes channels; ${id} is stacked on ${decoders[position - 1]?.id ?? ""}.`,
      );
    for (const name of mapped)
      if (!names.has(name) || /[:=,]/u.test(name))
        throw new LogicInputRejected(
          "decoders",
          `${id} maps a channel to "${name}", which is not an addressable logic channel; channels: ${[...names].join(", ")}`,
        );
  });
  if (Object.keys(decoders[0]?.channels ?? {}).length === 0)
    throw new LogicInputRejected(
      "decoders",
      "The bottom decoder needs at least one channel mapping, such as {rx: 'D0'}.",
    );
};

/** Read a caller-selected sigrok session and optionally run decoders on it. */
export class LogicCaptureInspector implements LogicCapturePort {
  readonly #pendingRoots = new Set<Runtime>();

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<Runtime> = () =>
      PrivateRuntimeRoot.create({ prefix: "rea-sigrok-" }),
  ) {}

  async close(): Promise<void> {
    const failures: string[] = [];
    for (const root of this.#pendingRoots)
      try {
        await root.close();
        this.#pendingRoots.delete(root);
      } catch {
        failures.push(root.path);
      }
    if (failures.length > 0)
      throw new ProviderCleanupError(
        LOGIC_CAPTURE_PROVIDER_IDENTITY.id,
        failures,
        {},
        { operation: OPERATION },
      );
  }

  async inspect(
    input: InspectLogicCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    let root: Runtime | undefined;
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_SESSION_SAMPLE_BYTES,
        signal,
      );
      if (selected.bytes.toString("latin1", 0, 4) !== "PK\x03\x04")
        throw new SigrokSessionError(
          "Expected a ZIP-based sigrok session (.sr).",
        );
      root = await this.createRuntime();
      const snapshot = join(root.path, SNAPSHOT);
      await writeFile(snapshot, selected.bytes, { flag: "wx", mode: 0o400 });
      const session = await readSigrokSession(snapshot, signal);
      const samples = session.logic.length / session.unitsize;
      const report: LogicCapture = logicCaptureSchema.parse({
        capture: {
          path: input.path,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
          sigrok_version: session.sigrokVersion,
          samplerate_hz: session.samplerate,
          samples,
          duration_s: samples / session.samplerate,
          unitsize: session.unitsize,
        },
        channels: session.logicChannels.map((channel) =>
          channelStatistics(session, channel),
        ),
        analog: session.analogChannels.map((channel) =>
          analogStatistics(
            channel,
            session.analog.get(channel.index) ?? new Float32Array(),
          ),
        ),
        decode:
          input.decoders === undefined
            ? null
            : await this.#decode(input, session, root.path, signal),
        limitations: LIMITATIONS,
      });
      result = ok(
        createAnalysisExecution(report, LOGIC_CAPTURE_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      result = err(failure(cause, input.path));
    }
    return this.#release(root, result);
  }

  async #decode(
    input: InspectLogicCaptureInput,
    session: SigrokSession,
    cwd: string,
    signal?: AbortSignal,
  ): Promise<LogicCapture["decode"]> {
    const decoders = input.decoders ?? [];
    checkStack(decoders, session);
    const run = {
      cwd,
      environment: this.environment,
      ...(signal === undefined ? {} : { signal }),
      ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
    };
    const profile = await sigrokProfile(this.environment, run);
    const top = decoders.at(-1)?.id ?? "";
    const commands: string[][] = [["-P", top, "--show"]];
    const classes = parseDecoderClasses(
      await runSigrok(profile.path, ["-P", top, "--show"], run),
    );
    const unknown = (input.annotations ?? []).filter(
      (wanted) => !classes.some(({ id }) => id === wanted),
    );
    if (unknown.length > 0)
      throw new LogicInputRejected(
        "annotations",
        `${top} has no annotation classes ${unknown.join(", ")}; classes: ${classes.map(({ id }) => id).join(", ")}`,
      );
    const stack = decoderStack(decoders);
    const selections = input.annotations ?? [null];
    type Decode = NonNullable<LogicCapture["decode"]>;
    const annotations: Decode["annotations"] = [];
    const totals: Decode["totals"] = [];
    const streams: Decode["byte_streams"] = [];
    for (const selection of selections) {
      const args = [
        "-i",
        SNAPSHOT,
        "-P",
        stack,
        ...(selection === null ? [] : ["-A", `${top}=${selection}`]),
        "--protocol-decoder-samplenum",
      ];
      commands.push(
        args.map((value) => (value === SNAPSHOT ? "<path>" : value)),
      );
      const parsed = parseAnnotations(
        await runSigrok(profile.path, args, run),
        selection,
        session.samplerate,
      );
      const kept = parsed.slice(0, input.annotation_limit);
      annotations.push(...kept);
      totals.push({
        class: selection,
        total: parsed.length,
        returned: kept.length,
      });
      const stream = selection === null ? null : byteStream(selection, parsed);
      if (stream !== null) streams.push(stream);
    }
    return {
      stack: [stack],
      classes,
      annotations,
      totals,
      byte_streams: streams,
      tool_profile: {
        tool: "sigrok-cli",
        version: profile.version,
        libsigrokdecode: profile.libsigrokdecode,
        executable_path: profile.path,
        executable_sha256: profile.sha256,
        arguments: commands,
        timeout_ms: SIGROK_LIMITS.timeoutMs,
      },
    };
  }

  async #release(
    root: Runtime | undefined,
    result: Result<AnalysisExecution, AnalysisError>,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (root === undefined) return result;
    try {
      await root.close();
      return result;
    } catch (cause: unknown) {
      this.#pendingRoots.add(root);
      return err(
        new ProviderCleanupError(
          LOGIC_CAPTURE_PROVIDER_IDENTITY.id,
          [root.path],
          { reason: cause instanceof Error ? cause.message : String(cause) },
          { operation: OPERATION, cause },
        ),
      );
    }
  }
}
