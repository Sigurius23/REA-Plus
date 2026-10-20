import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectGodotFileInput } from "../../domain/godot/godotFile.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline Godot file reader; resources, scripts and saves are decoded, never loaded or run. */
export interface GodotFilePort {
  close(): Promise<void>;
  inspect(
    input: InspectGodotFileInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
