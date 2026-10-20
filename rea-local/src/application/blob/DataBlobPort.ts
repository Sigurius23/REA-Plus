import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectDataBlobInput } from "../../domain/blob/dataBlob.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline data blob reader; payloads are decoded, never run. */
export interface DataBlobPort {
  close(): Promise<void>;
  inspect(
    input: InspectDataBlobInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
