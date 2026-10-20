import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { DiffBinariesInput } from "../../domain/bindiff/binaryDiff.js";
import type { Result } from "../../domain/result.js";

/** Replaceable whole-binary diffing over the configured analysis provider. */
export interface BinaryDiffPort {
  close(): Promise<void>;
  inspect(
    input: DiffBinariesInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
