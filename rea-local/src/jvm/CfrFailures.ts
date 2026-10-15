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
import { CFR_LIMITS, CFR_PROVIDER_IDENTITY } from "./CfrRelease.js";
import { JvmClassFormatError } from "./JvmClassFile.js";

const OPERATION = "inspect_jvm_artifact";

/**
 * Remove the JVM's "Picked up JAVA_TOOL_OPTIONS: ..." notices. They echo the
 * ambient environment, which REA+ does not persist merely because the child
 * inherited it.
 */
export const withoutJvmEnvironmentNotices = (text: string): string =>
  text
    .split(/(?<=\n)/u)
    .filter(
      (line) =>
        !/^Picked up (?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS):/u.test(
          line,
        ),
    )
    .join("");

/** Map lifecycle and format failures to typed errors without partial success. */
export const cfrFailure = (
  cause: unknown,
  phase: "configuration" | "artifact" | "producer",
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
  if (phase === "configuration")
    return new AnalysisCapabilityUnavailableError(
      CFR_PROVIDER_IDENTITY.id,
      OPERATION,
      reason,
      {
        cause,
        userMessage: `${reason} Supply CFR 0.152 via absolute REA_CFR_JAR and a Java runtime via JAVA_HOME or PATH; REA+ does not install tools.`,
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
  if (
    phase === "artifact" ||
    cause instanceof JvmClassFormatError ||
    cause instanceof ArtifactReaderFailure
  )
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["path"], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisOutputError(OPERATION, reason, { cause });
};

const commandFailure = (
  cause: OwnedCommandFailure,
  phase: "configuration" | "artifact" | "producer",
): AnalysisError => {
  const capturedOutput =
    cause.snapshot === null
      ? undefined
      : {
          stdout: cause.snapshot.stdout.text,
          stderr: withoutJvmEnvironmentNotices(cause.snapshot.stderr.text),
          truncated: cause.snapshot.diagnosticTruncated ?? false,
        };
  const options =
    capturedOutput === undefined ? { cause } : { cause, capturedOutput };
  if (cause.cleanupFailure !== null)
    return new ProviderCleanupError(
      CFR_PROVIDER_IDENTITY.id,
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
    return new AnalysisTimeoutError(OPERATION, CFR_LIMITS.timeoutMs, options);
  if (phase === "configuration")
    return new AnalysisCapabilityUnavailableError(
      CFR_PROVIDER_IDENTITY.id,
      OPERATION,
      cause.message,
      {
        ...options,
        userMessage:
          "The configured Java runtime or CFR jar could not start; inspect the retained diagnostics and check JAVA_HOME and REA_CFR_JAR.",
      },
    );
  return new AnalysisOutputError(OPERATION, cause.message, options);
};
