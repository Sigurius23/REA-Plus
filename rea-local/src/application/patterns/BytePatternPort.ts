import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ScanBytePatternsInput } from "../../domain/patterns/bytePatterns.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline AOB scanner over caller-selected files. */
export interface BytePatternPort {
  close(): Promise<void>;
  scan(
    input: ScanBytePatternsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
