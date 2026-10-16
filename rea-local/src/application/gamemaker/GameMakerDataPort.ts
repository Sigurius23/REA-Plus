import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectGameMakerDataInput } from "../../domain/gamemaker/gameMakerData.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline GameMaker data reader; game data is decoded, never run. */
export interface GameMakerDataPort {
  close(): Promise<void>;
  inspect(
    input: InspectGameMakerDataInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
