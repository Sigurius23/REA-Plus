import { finished } from "node:stream/promises";

import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type ProviderProcessStopResult,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";

/**
 * Largest single radare2 reply REA+ buffers. A complete `aflj` inventory is
 * roughly 600 bytes per function, so this admits over 200,000 functions.
 */
export const RADARE2_MAX_REPLY_BYTES = 128 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES = 256 * 1024;
const STARTUP_COMMAND = "<startup>";

/** Injectable acquisition seam; production owns a POSIX group or Windows job. */
export type Radare2Launcher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

/** Why the pipe can no longer produce a complete reply. */
export type Radare2PipeFailureReason =
  | "cancelled"
  | "timeout"
  | "output-limit"
  | "exited"
  | "protocol";

/** Terminal pipe failure; the owning client must stop and replace the process. */
export class Radare2PipeFailure extends Error {
  readonly command: string;
  readonly stderr: string;

  constructor(
    readonly reason: Radare2PipeFailureReason,
    message: string,
    details: { readonly command: string; readonly stderr: string },
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "Radare2PipeFailure";
    this.command = details.command;
    this.stderr = details.stderr;
  }
}

interface PendingReply {
  readonly command: string;
  readonly chunks: Buffer[];
  bytes: number;
  readonly resolve: (text: string) => void;
  readonly reject: (failure: Radare2PipeFailure) => void;
}

/** Spawn coordinates for one radare2 `-q0` session. */
export interface Radare2PipeOptions {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly cwd: string;
  readonly runId: string;
  readonly hostEnvironment: NodeJS.ProcessEnv;
  readonly launcher?: Radare2Launcher;
}

/**
 * One owned radare2 process speaking the r2pipe spawn protocol: each command
 * is a line on stdin and each reply ends with a single NUL byte on stdout.
 */
export class Radare2Pipe {
  #pending: PendingReply | undefined;
  #failure: Radare2PipeFailure | undefined;

  private constructor(
    private readonly spawned: SpawnedOwnedProviderProcess,
    private readonly supervisor: ProviderProcessSupervisor,
  ) {}

  /** Launch radare2 and wait for the NUL that ends its startup output. */
  static async start(
    options: Radare2PipeOptions,
    signal: AbortSignal,
  ): Promise<Radare2Pipe> {
    const spawned = await (options.launcher ?? spawnOwnedProviderProcess)({
      command: options.executable,
      arguments: options.arguments,
      cwd: options.cwd,
      runId: options.runId,
      hostEnvironment: options.hostEnvironment,
      stdin: "pipe",
      signal,
    });
    const supervisor = new ProviderProcessSupervisor(
      {
        ...spawned,
        ownsProcessLifetime: true,
        cleanup:
          spawned.cleanup ??
          (() => cleanupOwnedProcessGroup(spawned.ownership)),
      },
      { captureStdout: false, maxDiagnosticBytes: MAX_DIAGNOSTIC_BYTES },
    );
    const pipe = new Radare2Pipe(spawned, supervisor);
    pipe.#attach();
    try {
      await pipe.#await(STARTUP_COMMAND, signal);
    } catch (cause: unknown) {
      await pipe.stop();
      throw cause;
    }
    return pipe;
  }

  /** The terminal failure, once one occurred. */
  get failure(): Radare2PipeFailure | undefined {
    return this.#failure;
  }

  /** Retained stderr, bounded and safe to return as provider diagnostics. */
  stderr(): string {
    return this.supervisor.snapshot().stderr.text;
  }

  /** Run one fixed command and return its complete reply text. */
  async command(command: string, signal?: AbortSignal): Promise<string> {
    if (/[\n\r\0]/u.test(command))
      throw new TypeError("radare2 commands must be a single line");
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#pending !== undefined)
      throw new Radare2PipeFailure(
        "protocol",
        "radare2 pipe received a command while another reply was pending",
        { command, stderr: this.stderr() },
      );
    const input = this.spawned.process.stdin;
    if (input === undefined || input === null)
      throw this.#fail("protocol", "radare2 stdin is not writable", command);
    const reply = this.#await(command, signal);
    input.write(`${command}\n`, (cause) => {
      if (cause !== null && cause !== undefined)
        this.#fail("exited", "radare2 stdin closed", command, cause);
    });
    return reply;
  }

  /** Stop the owned process group; incomplete cleanup is reported, not hidden. */
  async stop(): Promise<ProviderProcessStopResult> {
    this.#fail("exited", "radare2 session stopped", STARTUP_COMMAND);
    const process = this.spawned.process;
    process.stdout?.off("data", this.#read);
    process.off("close", this.#closed);
    const input = process.stdin;
    const inputClosed =
      input === undefined || input === null
        ? undefined
        : finished(input, { readable: false, cleanup: true }).catch(
            () => undefined,
          );
    const stopped = await this.supervisor.stop();
    input?.destroy();
    await inputClosed;
    input?.off("error", this.#inputError);
    return stopped;
  }

  #attach(): void {
    const process = this.spawned.process;
    if (process.stdout === null)
      throw new TypeError("radare2 launcher did not supply protocol stdout");
    process.stdout.on("data", this.#read);
    process.stdin?.on("error", this.#inputError);
    // Close follows stdout drain, so a reply already written is never lost.
    process.once("close", this.#closed);
  }

  #await(command: string, signal?: AbortSignal): Promise<string> {
    if (this.#failure !== undefined) return Promise.reject(this.#failure);
    return new Promise<string>((resolve, reject) => {
      const onAbort = (): void => {
        this.#fail(
          signal?.reason instanceof DOMException &&
            signal.reason.name === "TimeoutError"
            ? "timeout"
            : "cancelled",
          "radare2 command was interrupted",
          command,
        );
      };
      const settle = (): void => signal?.removeEventListener("abort", onAbort);
      this.#pending = {
        command,
        chunks: [],
        bytes: 0,
        resolve: (text) => {
          settle();
          resolve(text);
        },
        reject: (failure) => {
          settle();
          reject(failure);
        },
      };
      if (signal?.aborted === true) onAbort();
      else signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  readonly #read = (chunk: Buffer | string): void => {
    let bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    while (bytes.length > 0) {
      const pending = this.#pending;
      if (pending === undefined) {
        if (this.#failure === undefined)
          this.#fail(
            "protocol",
            "radare2 wrote output outside a command reply",
            "<idle>",
          );
        return;
      }
      const terminator = bytes.indexOf(0);
      const part = terminator === -1 ? bytes : bytes.subarray(0, terminator);
      pending.bytes += part.length;
      if (pending.bytes > RADARE2_MAX_REPLY_BYTES) {
        this.#fail(
          "output-limit",
          `radare2 reply exceeded ${String(RADARE2_MAX_REPLY_BYTES)} bytes`,
          pending.command,
        );
        return;
      }
      pending.chunks.push(Buffer.from(part));
      if (terminator === -1) return;
      this.#pending = undefined;
      pending.resolve(Buffer.concat(pending.chunks).toString("utf8"));
      bytes = bytes.subarray(terminator + 1);
    }
  };

  readonly #closed = (): void => {
    this.#fail(
      "exited",
      "radare2 exited before completing the reply",
      this.#pending?.command ?? "<idle>",
    );
  };

  readonly #inputError = (cause: Error): void => {
    this.#fail(
      "exited",
      "radare2 stdin closed",
      this.#pending?.command ?? "<idle>",
      cause,
    );
  };

  #fail(
    reason: Radare2PipeFailureReason,
    message: string,
    command: string,
    cause?: unknown,
  ): Radare2PipeFailure {
    if (this.#failure !== undefined) return this.#failure;
    const pending = this.#pending;
    const failure = new Radare2PipeFailure(
      reason,
      message,
      { command: pending?.command ?? command, stderr: this.stderr() },
      cause === undefined ? undefined : { cause },
    );
    this.#failure = failure;
    this.#pending = undefined;
    pending?.reject(failure);
    return failure;
  }
}
