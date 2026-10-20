import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectJvmArtifactInput } from "../../domain/jvm/jvmArtifact.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline JVM decompiler, independent of target execution. */
export interface JvmArtifactPort {
  /** Retry removal of retained workspaces; failures preserve ownership. */
  close(): Promise<void>;
  inspect(
    input: InspectJvmArtifactInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
