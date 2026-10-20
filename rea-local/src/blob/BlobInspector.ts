import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { DataBlobPort } from "../application/blob/DataBlobPort.js";
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
  dataBlobSchema,
  type InspectDataBlobInput,
} from "../domain/blob/dataBlob.js";
import { err, ok, type Result } from "../domain/result.js";
import { buildDataBlobReport } from "./BlobReport.js";
import { BlobFormatError, BlobSelectionError } from "./BlobTree.js";

const OPERATION = "inspect_data_blob";
const MAX_FILE_BYTES = 512 * 1024 * 1024;

export const DATA_BLOB_PROVIDER_IDENTITY = {
  id: "data-blob-reader",
  name: "REA+ data blob reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Decodes without a schema: protobuf field numbers carry no names or declared types, so a varint, fixed32 or fixed64 is shown with its other readings, and a length-delimited field is a nested message whenever its bytes parse as one (protoc --decode_raw's rule).",
  "Auto detection keeps every format that decodes the whole payload and ranks them; short or random payloads can decode as more than one format, so check the candidates or name the format.",
  "Base64, hex, gzip, zlib, zstd and LZ4 frames are removed automatically; raw deflate and Brotli have no signature and must be named in layers. Encryption, XOR masks and custom framing are not undone.",
  "JSON nodes carry no byte offsets of their own; they span the whole text.",
  "Region files: Anvil .mca/.mcr chunks in gzip, zlib, LZ4 or uncompressed storage; external .mcc chunks are not read.",
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
  if (cause instanceof BlobSelectionError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof BlobFormatError || cause instanceof RangeError
          ? `Not a readable blob: ${reason}`
          : reason,
    },
  ]);
};

/** Decode a caller-selected blob; nothing is run. */
export class DataBlobInspector implements DataBlobPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectDataBlobInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_FILE_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = dataBlobSchema.parse(
        buildDataBlobReport(selected, input, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, DATA_BLOB_PROVIDER_IDENTITY, {
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
