import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectIl2CppMetadataInput } from "../../domain/il2cpp/il2cppMetadata.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline IL2CPP metadata reader, independent of target execution. */
export interface Il2CppMetadataPort {
  /** Drop cached listings and retry removal of retained workspaces. */
  close(): Promise<void>;
  inspect(
    input: InspectIl2CppMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
