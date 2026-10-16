import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectLogicCaptureInput } from "../../domain/logic/logicCapture.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline logic-analyzer session reader. */
export interface LogicCapturePort {
  /** Retry removal of retained workspaces. */
  close(): Promise<void>;
  inspect(
    input: InspectLogicCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
