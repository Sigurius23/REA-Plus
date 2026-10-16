import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectUnityAssetsInput } from "../../domain/unity/unityAssets.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline Unity asset reader, independent of the Unity runtime. */
export interface UnityAssetsPort {
  close(): Promise<void>;
  inspect(
    input: InspectUnityAssetsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
