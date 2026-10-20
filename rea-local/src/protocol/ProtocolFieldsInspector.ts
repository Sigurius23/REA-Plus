import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { ProtocolFieldsPort } from "../application/protocol/ProtocolFieldsPort.js";
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
  protocolFieldsSchema,
  type InferProtocolFieldsInput,
} from "../domain/protocol/protocolFields.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ProtocolFormatError,
  ProtocolSelectionError,
} from "./CaptureFrames.js";
import { buildProtocolReport } from "./ProtocolReport.js";

const OPERATION = "infer_protocol_fields";
const MAX_FILE_BYTES = 1024 * 1024 * 1024;

export const PROTOCOL_FIELDS_PROVIDER_IDENTITY = {
  id: "protocol-field-inference",
  name: "REA+ protocol field inference",
  version: "1",
} as const;

const LIMITATIONS = [
  "Fields are inferred from the messages alone, at fixed offsets within each format: a field after a variable-length one is not found, adjacent fields that never change merge into one constant run, and a format seen in only a few messages yields little. Treat every field as a hypothesis to test.",
  "Formats are told apart by a type field (one or two bytes in the first eight), by direction, or for text by the first word; protocols that tell formats apart otherwise are analysed as one format.",
  "TCP streams are reassembled by sequence number and split where data is missing; framing is a length prefix that tiles every stream, a line or NUL delimiter, or the segments as sent. Encrypted or compressed payloads (TLS, QUIC, zlib) show no structure.",
  "Checksums are recognised among CRC-32, CRC-32C, Adler-32, four CRC-16 variants, Fletcher-16, the internet checksum, and 8- and 16-bit sums and XOR; timestamps only as seconds, milliseconds or microseconds since 1970 within a day of the capture's clock. Only the first 5000 messages are analysed.",
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
  if (cause instanceof ProtocolSelectionError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof ProtocolFormatError || cause instanceof RangeError
          ? `Not a readable capture: ${reason}`
          : reason,
    },
  ]);
};

/** Infer message formats from a caller-selected capture; nothing is sent or replayed. */
export class ProtocolFieldsInspector implements ProtocolFieldsPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InferProtocolFieldsInput,
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
      const report = protocolFieldsSchema.parse(
        buildProtocolReport(selected, input, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, PROTOCOL_FIELDS_PROVIDER_IDENTITY, {
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
