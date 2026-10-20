import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectX64dbgDatabaseInput } from "../../domain/x64dbg/x64dbgDatabase.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline x64dbg database reader; nothing is attached to or run. */
export interface X64dbgDatabasePort {
  close(): Promise<void>;
  inspect(
    input: InspectX64dbgDatabaseInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
