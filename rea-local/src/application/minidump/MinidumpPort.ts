import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectMinidumpInput } from "../../domain/minidump/minidump.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline minidump reader, independent of target execution. */
export interface MinidumpPort {
  close(): Promise<void>;
  inspect(
    input: InspectMinidumpInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
