import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { access, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import type {
  ProviderProcessSnapshot,
  ProviderProcessSupervisor,
} from "../process/ProviderProcess.js";

export const MAX_COMMAND_OUTPUT_BYTES = 512 * 1024;
export const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;
export const FRIDA_RUNNER_PATH = fileURLToPath(
  new URL("../../bridge/frida/rea_frida_runner.py", import.meta.url),
);

const COMMAND_ENVIRONMENT_KEYS = [
  "PATH",
  "PATHEXT",
  "HOME",
  "USERPROFILE",
  "SYSTEMROOT",
  "WINDIR",
  "TMPDIR",
  "TMP",
  "TEMP",
] as const;

export interface MobileRuntimeCommandOutput {
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly exitCode: number | null;
  readonly signal: string | null;
}

export interface MobileRuntimeCommandRunner {
  run(
    command: string,
    args: readonly string[],
    options: {
      readonly timeoutMs: number;
      readonly signal?: AbortSignal;
      readonly acceptNonZeroExit: boolean;
    },
  ): Promise<MobileRuntimeCommandOutput>;
}

const safeEnvironment = (
  selected: Readonly<Record<string, string | undefined>>,
): NodeJS.ProcessEnv => {
  const result: NodeJS.ProcessEnv = {};
  for (const key of COMMAND_ENVIRONMENT_KEYS) {
    const value = selected[key];
    if (value !== undefined && !value.startsWith("()")) result[key] = value;
  }
  return result;
};

export const createDefaultMobileRuntimeCommandRunner = (
  selectedEnvironment: Readonly<Record<string, string | undefined>>,
  onCleanupOwner: (owner: ProviderProcessSupervisor) => void,
): MobileRuntimeCommandRunner => {
  const environment = safeEnvironment(selectedEnvironment);
  return {
    async run(command, args, options) {
      try {
        const snapshot = await runOwnedCommand(
          {
            command,
            arguments: args,
            runId: randomUUID(),
            hostEnvironment: environment,
          },
          {
            timeoutMs: options.timeoutMs,
            diagnosticBytes: MAX_COMMAND_OUTPUT_BYTES,
            acceptNonZeroExit: options.acceptNonZeroExit,
          },
          options.signal === undefined ? {} : { signal: options.signal },
        );
        return commandOutput(snapshot);
      } catch (cause) {
        if (cause instanceof OwnedCommandFailure) {
          if (cause.cleanupOwner !== undefined)
            onCleanupOwner(cause.cleanupOwner);
          throw cause;
        }
        throw new OwnedCommandFailure(
          "process",
          "Runtime command could not be completed.",
          null,
          null,
          { cause },
        );
      }
    },
  };
};

const commandOutput = (
  snapshot: ProviderProcessSnapshot,
): MobileRuntimeCommandOutput => ({
  stdout: snapshot.stdout.text,
  stderr: snapshot.stderr.text,
  stdoutBytes: snapshot.stdout.observedBytes,
  stderrBytes: snapshot.stderr.observedBytes,
  exitCode: snapshot.exitCode ?? null,
  signal: snapshot.signal ?? null,
});

export const hashRegularFile = async (path: string): Promise<string> => {
  const metadata = await stat(path);
  if (!metadata.isFile())
    throw new Error("selected command is not a regular file");
  if (metadata.size > MAX_EXECUTABLE_BYTES)
    throw new Error(
      "selected command exceeds the executable verification limit",
    );
  await access(
    path,
    process.platform === "win32"
      ? fsConstants.R_OK
      : fsConstants.R_OK | fsConstants.X_OK,
  );
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_EXECUTABLE_BYTES)
      throw new Error(
        "selected command changed beyond the executable verification limit",
      );
    hash.update(chunk);
  }
  const after = await stat(path);
  if (
    after.size !== metadata.size ||
    after.mtimeMs !== metadata.mtimeMs ||
    after.ino !== metadata.ino ||
    after.dev !== metadata.dev
  )
    throw new Error("selected command changed during executable verification");
  return `sha256:${hash.digest("hex")}`;
};

export const parseFridaRunnerResponse = (
  output: MobileRuntimeCommandOutput,
  operation: string,
): Result<Readonly<Record<string, unknown>>, AnalysisError> => {
  const marker = "__REA_FRIDA_JSON__";
  const line = output.stdout
    .split(/\r?\n/u)
    .reverse()
    .find((candidate) => candidate.startsWith(marker));
  if (line === undefined)
    return err(
      new AnalysisProtocolError(
        `Frida helper returned no response for ${operation}`,
        {
          capturedOutput: {
            stdout: output.stdout.slice(-1024),
            stderr: output.stderr.slice(-1024),
            truncated:
              output.stdout.length > 1024 || output.stderr.length > 1024,
            stdout_bytes: output.stdoutBytes,
            stderr_bytes: output.stderrBytes,
            exit_code: output.exitCode,
            signal: output.signal,
          },
        },
      ),
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(line.slice(marker.length)) as unknown;
  } catch (cause) {
    return err(
      new AnalysisProtocolError(
        `Frida helper returned invalid JSON for ${operation}`,
        {
          cause,
          capturedOutput: {
            stdout: output.stdout.slice(-1024),
            stderr: output.stderr.slice(-1024),
            truncated:
              output.stdout.length > 1024 || output.stderr.length > 1024,
            stdout_bytes: output.stdoutBytes,
            stderr_bytes: output.stderrBytes,
            exit_code: output.exitCode,
            signal: output.signal,
          },
        },
      ),
    );
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !("ok" in parsed)
  )
    return err(
      new AnalysisProtocolError(
        `Frida helper response was malformed for ${operation}`,
      ),
    );
  const record = parsed as Record<string, unknown>;
  if (record.ok !== true) {
    const detail =
      record.error !== null &&
      typeof record.error === "object" &&
      !Array.isArray(record.error) &&
      "message" in record.error &&
      typeof record.error.message === "string"
        ? record.error.message
        : "Frida helper reported an unspecified runtime error";
    if (detail.includes("Frida Python bindings are unavailable"))
      return err(
        new AnalysisCapabilityUnavailableError(
          "frida",
          operation,
          `${detail}. Install the Frida Python bindings in the configured interpreter.`,
        ),
      );
    return err(
      new AnalysisProtocolError(
        `Frida helper failed for ${operation}: ${detail}`,
      ),
    );
  }
  if (
    record.result === null ||
    typeof record.result !== "object" ||
    Array.isArray(record.result)
  )
    return err(
      new AnalysisProtocolError(
        `Frida helper result was malformed for ${operation}`,
      ),
    );
  return ok(record.result as Readonly<Record<string, unknown>>);
};
