import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectRpgMakerProjectInput } from "../../domain/rpgmaker/rpgMakerProject.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline RPG Maker MV/MZ reader; game files are decoded, never run. */
export interface RpgMakerProjectPort {
  close(): Promise<void>;
  inspect(
    input: InspectRpgMakerProjectInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
