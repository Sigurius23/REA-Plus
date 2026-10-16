import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
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
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { OwnedCommandFailure } from "../process/OwnedCommand.js";
import { R2UNITY_LIMITS, R2UNITY_PROVIDER_IDENTITY } from "./R2UnityRelease.js";

const OPERATION = "inspect_il2cpp_metadata";
/** Diagnostics kept on an error; a failed listing can be hundreds of MiB. */
const CAPTURED_OUTPUT_BYTES = 64 * 1024;

export type R2UnityPhase = "configuration" | "artifact" | "producer";

/** A selected file failed admission before any r2unity process ran. */
export class Il2CppInputRejected extends Error {
  constructor(
    readonly field: "metadata_path" | "binary_path" | "code_registration",
    message: string,
  ) {
    super(message);
  }
}

const bounded = (text: string): string =>
  text.length <= CAPTURED_OUTPUT_BYTES
    ? text
    : `${text.slice(0, CAPTURED_OUTPUT_BYTES)}\n[truncated by REA+]`;

/** Map lifecycle and format failures to typed errors without partial success. */
export const r2unityFailure = (
  cause: unknown,
  phase: R2UnityPhase,
  path: string,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof OwnedCommandFailure) return commandFailure(cause, phase);
  if (cause instanceof Il2CppInputRejected)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  if (phase === "configuration")
    return new AnalysisCapabilityUnavailableError(
      R2UNITY_PROVIDER_IDENTITY.id,
      OPERATION,
      reason,
      {
        cause,
        userMessage: `${reason} Build r2unity 1.2.8 or a later 1.2 release (https://github.com/radareorg/r2unity) and set absolute REA_R2UNITY_PATH; REA+ does not install tools.`,
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, {
      cause,
    });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  if (phase === "artifact" || cause instanceof ArtifactReaderFailure)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["metadata_path"], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisOutputError(OPERATION, reason, { cause });
};

const commandFailure = (
  cause: OwnedCommandFailure,
  phase: R2UnityPhase,
): AnalysisError => {
  const capturedOutput =
    cause.snapshot === null
      ? undefined
      : {
          stdout: bounded(cause.snapshot.stdout.text),
          stderr: bounded(cause.snapshot.stderr.text),
          truncated:
            (cause.snapshot.diagnosticTruncated ?? false) ||
            cause.snapshot.stdout.text.length > CAPTURED_OUTPUT_BYTES ||
            cause.snapshot.stderr.text.length > CAPTURED_OUTPUT_BYTES,
        };
  const options =
    capturedOutput === undefined ? { cause } : { cause, capturedOutput };
  if (cause.cleanupFailure !== null)
    return new ProviderCleanupError(
      R2UNITY_PROVIDER_IDENTITY.id,
      cause.resources,
      {
        reason: cause.cleanupFailure,
        previous_error: cause.message,
        ...(capturedOutput === undefined
          ? {}
          : { captured_output: capturedOutput }),
      },
      { operation: OPERATION, cause },
    );
  if (cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, options);
  if (cause.reason === "timeout")
    return new AnalysisTimeoutError(
      OPERATION,
      R2UNITY_LIMITS.timeoutMs,
      options,
    );
  if (phase === "configuration")
    return new AnalysisCapabilityUnavailableError(
      R2UNITY_PROVIDER_IDENTITY.id,
      OPERATION,
      cause.message,
      {
        ...options,
        userMessage:
          "The configured r2unity executable could not start; it links radare2's libraries, so check that they are on the loader path. Inspect the retained diagnostics and REA_R2UNITY_PATH.",
      },
    );
  if (cause.reason === "output-limit")
    return new AnalysisOutputError(
      OPERATION,
      `r2unity output exceeded the ${String(R2UNITY_LIMITS.outputBytes)}-byte budget for one listing.`,
      options,
    );
  return new AnalysisOutputError(
    OPERATION,
    "r2unity failed; inspect its retained diagnostics.",
    options,
  );
};
