import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectLuaBytecodeInput } from "../../domain/lua/luaBytecode.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline Lua bytecode reader; chunks are decoded, never loaded or run. */
export interface LuaBytecodePort {
  close(): Promise<void>;
  inspect(
    input: InspectLuaBytecodeInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
