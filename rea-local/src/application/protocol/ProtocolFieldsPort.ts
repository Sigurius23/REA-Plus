import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InferProtocolFieldsInput } from "../../domain/protocol/protocolFields.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline protocol field inference; captures are read, never replayed. */
export interface ProtocolFieldsPort {
  close(): Promise<void>;
  inspect(
    input: InferProtocolFieldsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
