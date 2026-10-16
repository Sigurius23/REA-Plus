import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectMobsfReportInput } from "../../domain/mobsf/mobsfReport.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline MobSF report reader; reports are parsed, MobSF is never contacted. */
export interface MobsfReportPort {
  close(): Promise<void>;
  inspect(
    input: InspectMobsfReportInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
