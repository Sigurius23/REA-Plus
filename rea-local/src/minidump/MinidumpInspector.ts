import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { MinidumpPort } from "../application/minidump/MinidumpPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  minidumpSchema,
  type InspectMinidumpInput,
} from "../domain/minidump/minidump.js";
import { err, ok, type Result } from "../domain/result.js";
import { MinidumpFormatError } from "./MinidumpFile.js";
import {
  buildMinidumpReport,
  MinidumpThreadNotFound,
} from "./MinidumpReport.js";

const OPERATION = "inspect_minidump";
/** Full-memory dumps are read into memory up to this size. */
const MAX_DUMP_BYTES = 2 * 1024 * 1024 * 1024;

export const MINIDUMP_PROVIDER_IDENTITY = {
  id: "minidump-reader",
  name: "REA+ minidump reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "The stack scan reports stack slots that point into module images; it is the classic return-address heuristic, not unwinding, and can include stale values or data pointers.",
  "Module identities come from the dump's own records (paths, code and debug identifiers); REA+ does not fetch symbols or confirm that files on this host match them.",
  "Register sets are decoded for x86, AMD64, ARM64 and 32-bit ARM contexts; other architectures report addresses only where the dump records them outside a context.",
  "Streams REA+ does not interpret are listed with their sizes; malformed streams are reported and the rest of the dump is still decoded.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof MinidumpThreadNotFound)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["thread_id"], reason: "invalid_value", message: reason },
    ]);
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
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof MinidumpFormatError
          ? `Not a readable minidump: ${reason}`
          : reason,
    },
  ]);
};

/** Read caller-selected minidumps; nothing is loaded, executed or symbolized. */
export class MinidumpInspector implements MinidumpPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectMinidumpInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_DUMP_BYTES,
        signal,
      );
      const report = minidumpSchema.parse(
        buildMinidumpReport(selected.bytes, input, selected, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, MINIDUMP_PROVIDER_IDENTITY, {
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
      return err(failure(cause, input.path));
    }
  }
}
