import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
  type ProviderIdentity,
} from "./AnalysisProvider.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";

type ErrorClass<E extends Error> = abstract new (...args: never[]) => E;

/** A caller-selection error reported against its own `field` member. */
export interface ArtifactSelfFieldError {
  readonly error: ErrorClass<Error & { readonly field: string }>;
}

/** A caller-selection error reported against a fixed input field. */
export interface ArtifactNamedFieldError {
  readonly error: ErrorClass<Error>;
  readonly field: string;
}

/** Errors an inspector reports against one input field, checked before integrity. */
export type ArtifactFieldError =
  | ArtifactSelfFieldError
  | ArtifactNamedFieldError;

/** Fixed metadata for the shared read-one-stable-artifact inspector flow. */
export interface ArtifactInspectorSpec {
  /** Provider operation name used in error attribution. */
  readonly operation: string;
  readonly identity: ProviderIdentity;
  /** The read refuses artifacts above this many bytes. */
  readonly maxFileBytes: number;
  /** Report schema every result is validated against. */
  readonly schema: { parse(value: unknown): unknown };
  /** Fixed disclosed limitations carried onto the execution when not on the report. */
  readonly limitations: readonly string[];
  /** Input errors reported against one field, checked in order first. */
  readonly fieldErrors?: readonly ArtifactFieldError[];
  /** Decoder format errors cited as "not readable"; RangeError is included where thrown. */
  readonly formatErrors: readonly ErrorClass<Error>[];
  /** Failure message prefix, as `${notReadable}: ${reason}`. */
  readonly notReadable: string;
  /** Carry the parsed report's own limitations onto the execution instead of `limitations`. */
  readonly reportLimitations?: boolean;
}

/** Map any caught cause into the inspector's typed analysis error. */
export const artifactInspectorFailure =
  (spec: {
    readonly operation: string;
    readonly fieldErrors?: readonly ArtifactFieldError[];
    readonly formatErrors: readonly ErrorClass<Error>[];
    readonly notReadable: string;
  }) =>
  (path: string) =>
  (cause: unknown): AnalysisError => {
    if (cause instanceof AnalysisCancelledError) return cause;
    const reason = cause instanceof Error ? cause.message : String(cause);
    if (
      (cause instanceof ArtifactReaderFailure &&
        cause.reason === "cancelled") ||
      (cause instanceof Error && cause.name === "AbortError")
    )
      return new AnalysisCancelledError(spec.operation, { cause });
    for (const entry of spec.fieldErrors ?? []) {
      if ("field" in entry) {
        if (cause instanceof entry.error)
          return new AnalysisInputError(spec.operation, { cause }, [
            { path: [entry.field], reason: "invalid_value", message: reason },
          ]);
        continue;
      }
      if (cause instanceof entry.error)
        return new AnalysisInputError(spec.operation, { cause }, [
          {
            path: [cause.field],
            reason: "invalid_value",
            message: reason,
          },
        ]);
    }
    if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
      return new AnalysisArtifactChangedError(spec.operation, path, reason, {
        cause,
      });
    if (
      cause instanceof Error &&
      "code" in cause &&
      (cause.code === "EACCES" || cause.code === "EPERM")
    )
      return new AnalysisAccessDeniedError(spec.operation, path, cause.code, {
        cause,
      });
    return new AnalysisInputError(spec.operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: spec.formatErrors.some((error) => cause instanceof error)
          ? `${spec.notReadable}: ${reason}`
          : reason,
      },
    ]);
  };

const artifactPathSubject = (path: string, sha256: string) =>
  ({
    subject: {
      path,
      format: "file",
      sha256,
    },
    locations: [{ kind: "artifact-path", path }],
  }) as const;

/**
 * One offline inspector per domain reads one SHA-256-verified artifact,
 * builds its report and wraps it in an execution; nothing is run.
 *
 * Every inspector caught by this shared flow keeps a fresh report builder;
 * the caller passes its domain's decoder and schema through `spec`.
 */
export const inspectSingleArtifact = <Input extends { readonly path: string }>(
  spec: ArtifactInspectorSpec,
  buildReport: (
    selected: { readonly bytes: Buffer; readonly sha256: string },
    input: Input,
    limitations: readonly string[],
  ) => unknown,
) => {
  const failure = artifactInspectorFailure(spec);
  return async (
    input: Input,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> => {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true)
        throw new AnalysisCancelledError(spec.operation);
      const selected = await readStableArtifact(
        input.path,
        spec.maxFileBytes,
        signal,
      );
      signal?.throwIfAborted();
      const report = spec.schema.parse(
        buildReport(selected, input, spec.limitations),
      );
      return ok(
        createAnalysisExecution(report, spec.identity, {
          ...artifactPathSubject(input.path, selected.sha256),
          ...(spec.reportLimitations === true
            ? {
                limitations: (report as { limitations: readonly string[] })
                  .limitations,
              }
            : { limitations: spec.limitations }),
        }),
      );
    } catch (cause: unknown) {
      return err(failure(input.path)(cause));
    }
  };
};
