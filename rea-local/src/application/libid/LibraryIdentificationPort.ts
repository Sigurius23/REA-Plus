import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { IdentifyLibraryFunctionsInput } from "../../domain/libid/libraryIdentification.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline library function identification; nothing is executed. */
export interface LibraryIdentificationPort {
  close(): Promise<void>;
  inspect(
    input: IdentifyLibraryFunctionsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
