import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { ProtocolFieldsPort } from "../application/protocol/ProtocolFieldsPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  protocolFieldsSchema,
  type InferProtocolFieldsInput,
} from "../domain/protocol/protocolFields.js";
import type { Result } from "../domain/result.js";
import {
  ProtocolFormatError,
  ProtocolSelectionError,
} from "./CaptureFrames.js";
import { buildProtocolReport } from "./ProtocolReport.js";

const OPERATION = "infer_protocol_fields";

export const PROTOCOL_FIELDS_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "protocol-field-inference",
  name: "REA+ protocol field inference",
  version: "1",
};

const LIMITATIONS = [
  "Fields are inferred from the messages alone, at fixed offsets within each format: a field after a variable-length one is not found, adjacent fields that never change merge into one constant run, and a format seen in only a few messages yields little. Treat every field as a hypothesis to test.",
  "Formats are told apart by a type field (one or two bytes in the first eight), by direction, or for text by the first word; protocols that tell formats apart otherwise are analysed as one format.",
  "TCP streams are reassembled by sequence number and split where data is missing; framing is a length prefix that tiles every stream, a line or NUL delimiter, or the segments as sent. Encrypted or compressed payloads (TLS, QUIC, zlib) show no structure.",
  "Checksums are recognised among CRC-32, CRC-32C, Adler-32, four CRC-16 variants, Fletcher-16, the internet checksum, and 8- and 16-bit sums and XOR; timestamps only as seconds, milliseconds or microseconds since 1970 within a day of the capture's clock. Only the first 5000 messages are analysed.",
];

const SPEC = {
  operation: OPERATION,
  identity: PROTOCOL_FIELDS_PROVIDER_IDENTITY,
  maxFileBytes: 1024 * 1024 * 1024,
  schema: protocolFieldsSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: ProtocolSelectionError }],
  formatErrors: [ProtocolFormatError, RangeError],
  notReadable: "Not a readable capture",
} as const;

/** Infer message formats from a caller-selected capture; nothing is sent or replayed. */
export const createProtocolFieldsInspector = (): ProtocolFieldsPort => {
  const inspect = inspectSingleArtifact<InferProtocolFieldsInput>(
    SPEC,
    (selected, input, limitations) =>
      buildProtocolReport(selected, input, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InferProtocolFieldsInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
