import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectCoverageLogInput } from "../../domain/drcov/coverageLog.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline coverage-log reader, independent of target execution. */
export interface CoverageLogPort {
  close(): Promise<void>;
  inspect(
    input: InspectCoverageLogInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
