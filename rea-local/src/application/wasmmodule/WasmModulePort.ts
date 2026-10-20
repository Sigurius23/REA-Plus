import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectWasmModuleInput } from "../../domain/wasmmodule/wasmModule.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline WebAssembly module reader; modules are decoded, never compiled or run. */
export interface WasmModulePort {
  close(): Promise<void>;
  inspect(
    input: InspectWasmModuleInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
