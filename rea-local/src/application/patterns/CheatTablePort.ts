import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectCheatTableInput } from "../../domain/patterns/cheatTable.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline Cheat Engine table reader. */
export interface CheatTablePort {
  close(): Promise<void>;
  inspect(
    input: InspectCheatTableInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
