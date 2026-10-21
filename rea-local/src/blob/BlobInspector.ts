import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { DataBlobPort } from "../application/blob/DataBlobPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  dataBlobSchema,
  type InspectDataBlobInput,
} from "../domain/blob/dataBlob.js";
import type { Result } from "../domain/result.js";
import { buildDataBlobReport } from "./BlobReport.js";
import { BlobFormatError, BlobSelectionError } from "./BlobTree.js";

const OPERATION = "inspect_data_blob";

export const DATA_BLOB_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "data-blob-reader",
  name: "REA+ data blob reader",
  version: "1",
};

const LIMITATIONS = [
  "Decodes without a schema: protobuf field numbers carry no names or declared types, so a varint, fixed32 or fixed64 is shown with its other readings, and a length-delimited field is a nested message whenever its bytes parse as one (protoc --decode_raw's rule).",
  "Auto detection keeps every format that decodes the whole payload and ranks them; short or random payloads can decode as more than one format, so check the candidates or name the format.",
  "Base64, hex, gzip, zlib, zstd and LZ4 frames are removed automatically; raw deflate and Brotli have no signature and must be named in layers. Encryption, XOR masks and custom framing are not undone.",
  "JSON nodes carry no byte offsets of their own; they span the whole text.",
  "Region files: Anvil .mca/.mcr chunks in gzip, zlib, LZ4 or uncompressed storage; external .mcc chunks are not read.",
];

const SPEC = {
  operation: OPERATION,
  identity: DATA_BLOB_PROVIDER_IDENTITY,
  maxFileBytes: 512 * 1024 * 1024,
  schema: dataBlobSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: BlobSelectionError }],
  formatErrors: [BlobFormatError, RangeError],
  notReadable: "Not a readable blob",
} as const;

/** Decode a caller-selected blob; nothing is run. */
export const createDataBlobInspector = (): DataBlobPort => {
  const inspect = inspectSingleArtifact<InspectDataBlobInput>(
    SPEC,
    (selected, input, limitations) =>
      buildDataBlobReport(selected, input, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectDataBlobInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> => inspect(input, options),
  };
};
