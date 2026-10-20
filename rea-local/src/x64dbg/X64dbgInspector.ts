import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { X64dbgDatabasePort } from "../application/x64dbg/X64dbgDatabasePort.js";
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
import {
  x64dbgDatabaseSchema,
  type InspectX64dbgDatabaseInput,
} from "../domain/x64dbg/x64dbgDatabase.js";
import { ImageLayoutError, readImageLayout } from "../patterns/ImageLayout.js";
import { UnityCompressionError } from "../unity/Lz4Block.js";
import {
  inflateDatabase,
  parseDatabase,
  X64dbgDatabaseError,
} from "./X64dbgDatabase.js";
import { buildX64dbgReport, type ModuleImage } from "./X64dbgReport.js";

const OPERATION = "inspect_x64dbg_database";
const MAX_DATABASE_BYTES = 256 * 1024 * 1024;
const MAX_MODULE_BYTES = 1024 * 1024 * 1024;

export const X64DBG_PROVIDER_IDENTITY = {
  id: "x64dbg-database-reader",
  name: "REA+ x64dbg database reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads the JSON database x64dbg saves under db/ (.dd32/.dd64), plain or LZ4-compressed; nothing is attached to or debugged.",
  "Addresses are relative to the named module's base, as x64dbg stores them; entries without a module are absolute addresses from that session.",
  "module_path places addresses in one module's file and checks software breakpoints' original bytes against it; other modules' entries are listed without offsets.",
  "Trace records, encode maps, address colours and per-module hashes are counted in sections, not decoded.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
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
  const unreadable =
    cause instanceof X64dbgDatabaseError ||
    cause instanceof UnityCompressionError;
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: [cause instanceof ImageLayoutError ? "module_path" : "path"],
      reason: "invalid_value",
      message: unreadable
        ? `Not a readable x64dbg database: ${reason}`
        : reason,
    },
  ]);
};

const moduleImage = async (
  path: string | undefined,
  signal: AbortSignal | undefined,
): Promise<ModuleImage | null> => {
  if (path === undefined) return null;
  const { bytes, sha256 } = await readStableArtifact(
    path,
    MAX_MODULE_BYTES,
    signal,
  );
  return { path, sha256, bytes, layout: readImageLayout(bytes) };
};

/** Read a caller-selected x64dbg database and, optionally, the module it describes. */
export class X64dbgInspector implements X64dbgDatabasePort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectX64dbgDatabaseInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_DATABASE_BYTES,
        signal,
      );
      const { json, compressed } = inflateDatabase(selected.bytes);
      const root = parseDatabase(json);
      const image = await moduleImage(input.module_path, signal);
      signal?.throwIfAborted();
      const report = x64dbgDatabaseSchema.parse(
        buildX64dbgReport(
          root,
          input,
          {
            database: {
              path: input.path,
              sha256: selected.sha256,
              bytes: selected.bytes.length,
              compressed,
              json_bytes: json.length,
            },
            image,
          },
          LIMITATIONS,
        ),
      );
      return ok(
        createAnalysisExecution(report, X64DBG_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [
            { kind: "artifact-path", path: input.path },
            ...(input.module_path === undefined
              ? []
              : [{ kind: "artifact-path" as const, path: input.module_path }]),
          ],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
