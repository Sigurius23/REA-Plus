import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  MobileRuntimeAnalysisPort,
  MobileRuntimeObservation,
} from "../application/mobileRuntime/MobileRuntimeAnalysisPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  mobileRuntimeRequestSchema,
  type MobileRuntimeRequest,
} from "../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { OwnedCommandFailure } from "../process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  createDefaultMobileRuntimeCommandRunner,
  FRIDA_RUNNER_PATH,
  hashRegularFile,
  MAX_COMMAND_OUTPUT_BYTES,
  parseFridaRunnerResponse,
  type MobileRuntimeCommandRunner,
} from "./MobileRuntimeProcessSupport.js";

export type { MobileRuntimeCommandRunner } from "./MobileRuntimeProcessSupport.js";

export interface MobileRuntimeProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** Narrow process seam for deterministic adapter tests. */
  readonly commandRunner?: MobileRuntimeCommandRunner;
  readonly runtimeRoot?: typeof PrivateRuntimeRoot.create;
}

/** Caller-selected, opt-in Frida and Objection subprocess adapter. */
export class MobileRuntimeProvider implements MobileRuntimeAnalysisPort {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #commandRunner: MobileRuntimeCommandRunner;
  readonly #createRuntimeRoot: typeof PrivateRuntimeRoot.create;
  readonly #pendingOwners = new Set<ProviderProcessSupervisor>();
  readonly #privateRuntimeRoots = new Set<PrivateRuntimeRoot>();
  readonly #shutdown = new AbortController();
  readonly #active = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: MobileRuntimeProviderOptions = {}) {
    this.#environment = snapshotEnvironment(options.environment ?? process.env);
    this.#createRuntimeRoot = options.runtimeRoot ?? PrivateRuntimeRoot.create;
    this.#commandRunner =
      options.commandRunner ??
      createDefaultMobileRuntimeCommandRunner(this.#environment, (owner) =>
        this.#pendingOwners.add(owner),
      );
  }

  execute(
    request: MobileRuntimeRequest,
    options?: ExecutionOptions,
  ): Promise<Result<MobileRuntimeObservation, AnalysisError>> {
    const parsed = mobileRuntimeRequestSchema.safeParse(request);
    if (!parsed.success) {
      const operation =
        typeof request?.operation === "string"
          ? request.operation
          : "mobile_runtime";
      return Promise.resolve(
        err(new AnalysisInputError(operation, { cause: parsed.error })),
      );
    }
    const validatedRequest = parsed.data;
    if (this.#closing)
      return Promise.resolve(
        err(new AnalysisCancelledError(validatedRequest.operation)),
      );
    const signal =
      options?.signal === undefined
        ? this.#shutdown.signal
        : AbortSignal.any([options.signal, this.#shutdown.signal]);
    return this.#track(this.#execute(validatedRequest, signal));
  }

  close(): Promise<void> {
    this.#closing = true;
    this.#shutdown.abort();
    this.#closePromise ??= this.#drainAndClean().catch((cause: unknown) => {
      this.#closePromise = undefined;
      throw cause;
    });
    return this.#closePromise;
  }

  #track<T>(operation: Promise<T>): Promise<T> {
    const settled = operation.then(
      () => undefined,
      () => undefined,
    );
    this.#active.add(settled);
    void settled.then(() => this.#active.delete(settled));
    return operation;
  }

  async #drainAndClean(): Promise<void> {
    await Promise.all(this.#active);
    const failures: unknown[] = [];
    for (const owner of this.#pendingOwners) {
      try {
        const stopped = await owner.stop();
        if (stopped.status === "incomplete") throw new Error(stopped.reason);
        this.#pendingOwners.delete(owner);
      } catch (cause) {
        failures.push(cause);
      }
    }
    for (const root of this.#privateRuntimeRoots) {
      try {
        await root.close();
        this.#privateRuntimeRoots.delete(root);
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(
        failures,
        "Frida/Objection resource cleanup failed",
      );
  }

  async #execute(
    request: MobileRuntimeRequest,
    signal: AbortSignal,
  ): Promise<Result<MobileRuntimeObservation, AnalysisError>> {
    if (signal.aborted)
      return err(new AnalysisCancelledError(request.operation));
    if (request.operation === "run_objection_command")
      return this.#runObjection(request, signal);
    return this.#runFrida(request, signal);
  }

  async #runFrida(
    request: Exclude<
      MobileRuntimeRequest,
      { operation: "run_objection_command" }
    >,
    signal: AbortSignal,
  ): Promise<Result<MobileRuntimeObservation, AnalysisError>> {
    const python = this.#environment.REA_FRIDA_PYTHON_PATH;
    const operation = request.operation;
    if (python === undefined || python.length === 0 || !isAbsolute(python))
      return err(
        new AnalysisCapabilityUnavailableError(
          "frida",
          operation,
          "Set REA_FRIDA_PYTHON_PATH to an absolute path for a Python interpreter with the Frida bindings installed.",
        ),
      );
    if (signal.aborted) return err(new AnalysisCancelledError(operation));

    let pythonHash: string;
    try {
      pythonHash = await hashRegularFile(python);
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "frida",
          operation,
          "The configured Python interpreter is not a readable regular file.",
          { cause },
        ),
      );
    }

    let root: PrivateRuntimeRoot;
    try {
      root = await this.#createRuntimeRoot();
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "frida",
          operation,
          `A private runtime directory could not be established: ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        ),
      );
    }

    this.#privateRuntimeRoots.add(root);
    let result: Result<MobileRuntimeObservation, AnalysisError>;
    const timeoutMs =
      request.operation === "run_frida_script"
        ? request.input.observation_ms + 15_000
        : 30_000;
    try {
      const requestPath = join(root.path, "request.json");
      await writeFile(requestPath, JSON.stringify(toHelperRequest(request)), {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      if (signal.aborted) {
        result = err(new AnalysisCancelledError(operation));
      } else {
        const output = await this.#commandRunner.run(
          python,
          [FRIDA_RUNNER_PATH, requestPath],
          { timeoutMs, signal, acceptNonZeroExit: true },
        );
        if (signal.aborted) {
          result = err(new AnalysisCancelledError(operation));
        } else {
          const response = parseFridaRunnerResponse(output, operation);
          if (!response.ok) {
            result = response;
          } else {
            result = this.#fridaObservation(
              request,
              pythonHash,
              response.value,
            );
          }
        }
      }
    } catch (cause) {
      result = signal.aborted
        ? err(new AnalysisCancelledError(operation))
        : this.#commandFailure(operation, cause, timeoutMs);
    }
    try {
      await root.close();
      this.#privateRuntimeRoots.delete(root);
    } catch (cause) {
      return err(
        new AnalysisProtocolError(
          `Private Frida runtime files could not be removed for ${operation}`,
          {
            cause,
          },
        ),
      );
    }
    return result;
  }

  #fridaObservation(
    request: Exclude<
      MobileRuntimeRequest,
      { operation: "run_objection_command" }
    >,
    pythonHash: string,
    source: Readonly<Record<string, unknown>>,
  ): Result<MobileRuntimeObservation, AnalysisError> {
    const payload = {
      ...source,
      python_executable_sha256: pythonHash,
      ...(request.operation === "run_frida_script"
        ? {
            script_sha256: `sha256:${createHash("sha256").update(request.input.script).digest("hex")}`,
            script_bytes: Buffer.byteLength(request.input.script, "utf8"),
          }
        : {}),
    };
    return ok({
      result: jsonValueSchema.parse(payload),
      provider: {
        id: "frida",
        name: "Frida",
        version:
          typeof source.frida_version === "string"
            ? source.frida_version
            : null,
      },
      limitations: [
        "Frida was caller-selected; REA+ does not install or update the interpreter or Frida bindings.",
        ...(request.operation === "run_frida_script"
          ? [
              "The caller-supplied script executes inside the selected process and may modify process state or persistent data; stopping the controller cannot roll back those effects.",
              "The controller timeout bounds REA+'s wait and terminates its owned helper process; it is not an operating-system sandbox for code already injected into the target.",
              ...(source.script_unloaded === true
                ? []
                : [
                    "Frida did not confirm that the caller script was unloaded; inspect the target before assuming the session is clean.",
                  ]),
              ...(source.detached === true
                ? []
                : [
                    "Frida did not confirm detachment from the target process; inspect the target before assuming the session is closed.",
                  ]),
            ]
          : []),
      ],
    });
  }

  async #runObjection(
    request: Extract<
      MobileRuntimeRequest,
      { operation: "run_objection_command" }
    >,
    signal: AbortSignal,
  ): Promise<Result<MobileRuntimeObservation, AnalysisError>> {
    const command = this.#environment.REA_OBJECTION_CMD_PATH;
    if (command === undefined || command.length === 0 || !isAbsolute(command))
      return err(
        new AnalysisCapabilityUnavailableError(
          "objection",
          request.operation,
          "Set REA_OBJECTION_CMD_PATH to an absolute path for the Objection CLI.",
        ),
      );
    if (signal.aborted)
      return err(new AnalysisCancelledError(request.operation));

    let executableHash: string;
    try {
      executableHash = await hashRegularFile(command);
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "objection",
          request.operation,
          "The configured Objection command is not a readable regular file.",
          { cause },
        ),
      );
    }

    const args = ["--name", request.input.target];
    if (request.input.device_serial !== undefined)
      args.push("--serial", request.input.device_serial);
    args.push("run", request.input.command);

    try {
      const output = await this.#commandRunner.run(command, args, {
        timeoutMs: request.input.timeout_ms,
        signal,
        acceptNonZeroExit: true,
      });
      if (signal.aborted)
        return err(new AnalysisCancelledError(request.operation));
      return ok({
        result: {
          target: request.input.target,
          device_serial: request.input.device_serial ?? null,
          command_sha256: `sha256:${createHash("sha256").update(request.input.command).digest("hex")}`,
          command_bytes: Buffer.byteLength(request.input.command, "utf8"),
          executable_sha256: executableHash,
          stdout: output.stdout,
          stderr: output.stderr,
          stdout_bytes: output.stdoutBytes,
          stderr_bytes: output.stderrBytes,
          output_truncated: false,
          exit_code: output.exitCode,
          signal: output.signal,
          timed_out: false,
        },
        provider: {
          id: "objection",
          name: "Objection",
          version: null,
        },
        limitations: [
          "Objection was caller-selected; REA+ does not install or update the CLI or its Frida dependencies.",
          "The command is interpreted by Objection and may modify the selected process, device, or application data; explicit confirmation is required and effects cannot be rolled back by REA+.",
          "The command is passed as one argument without a host shell; Objection's own command language remains active.",
        ],
      });
    } catch (cause) {
      return signal.aborted
        ? err(new AnalysisCancelledError(request.operation))
        : this.#commandFailure(
            request.operation,
            cause,
            request.input.timeout_ms,
          );
    }
  }

  #commandFailure(
    operation: string,
    cause: unknown,
    timeoutMs: number,
  ): Result<never, AnalysisError> {
    if (!(cause instanceof OwnedCommandFailure))
      return err(
        new AnalysisProtocolError(`Runtime command failed for ${operation}`, {
          cause,
        }),
      );
    const capturedOutput =
      cause.snapshot === null
        ? undefined
        : {
            stdout: cause.snapshot.stdout.text,
            stderr: cause.snapshot.stderr.text,
            stdout_bytes: cause.snapshot.stdout.observedBytes,
            stderr_bytes: cause.snapshot.stderr.observedBytes,
            exit_code: cause.snapshot.exitCode ?? null,
            signal: cause.snapshot.signal ?? null,
            truncated: cause.snapshot.diagnosticTruncated === true,
          };
    const cleanup =
      cause.cleanupFailure === null
        ? undefined
        : {
            reason: cause.cleanupFailure,
            resources: cause.resources,
          };
    const details = {
      cause,
      ...(cleanup === undefined ? {} : { cleanup }),
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
    };
    if (cause.reason === "cancelled")
      return err(new AnalysisCancelledError(operation, details));
    if (cause.reason === "timeout")
      return err(new AnalysisTimeoutError(operation, timeoutMs, details));
    if (cause.reason === "output-limit")
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "transport",
          `Runtime command output exceeded the ${String(MAX_COMMAND_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: MAX_COMMAND_OUTPUT_BYTES },
          details,
        ),
      );
    return err(
      new AnalysisOutputError(
        operation,
        "runtime command exited unsuccessfully",
        details,
      ),
    );
  }
}

const toHelperRequest = (
  request: Exclude<
    MobileRuntimeRequest,
    { operation: "run_objection_command" }
  >,
): Record<string, unknown> => {
  if (request.operation === "list_frida_devices")
    return { operation: "list_devices" };
  if (request.operation === "list_frida_processes")
    return {
      operation: "list_processes",
      device_id: request.input.device_id ?? null,
    };
  return {
    operation: "run_script",
    device_id: request.input.device_id ?? null,
    pid: request.input.pid,
    script: request.input.script,
    observation_ms: request.input.observation_ms,
  };
};
