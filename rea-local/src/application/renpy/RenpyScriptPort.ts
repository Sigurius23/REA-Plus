import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectRenpyScriptInput } from "../../domain/renpy/renpyScript.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline Ren'Py script reader; scripts are decoded, never run. */
export interface RenpyScriptPort {
  close(): Promise<void>;
  inspect(
    input: InspectRenpyScriptInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
