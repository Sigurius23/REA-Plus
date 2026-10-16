import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectGameArchiveInput } from "../../domain/gamearchives/gameArchive.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline game archive reader; archives are parsed, never mounted. */
export interface GameArchivePort {
  close(): Promise<void>;
  inspect(
    input: InspectGameArchiveInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
