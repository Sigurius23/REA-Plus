import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { MobileRuntimeRequest } from "../../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";

export interface MobileRuntimeProviderIdentity {
  readonly id: string;
  readonly name: string;
  readonly version: string | null;
}

export interface MobileRuntimeObservation {
  readonly result: JsonValue;
  readonly provider: MobileRuntimeProviderIdentity;
  readonly limitations: readonly string[];
}

/** Caller-selected Frida/Objection operations with owned process lifetime. */
export interface MobileRuntimeAnalysisPort {
  execute(
    request: MobileRuntimeRequest,
    options?: ExecutionOptions,
  ): Promise<Result<MobileRuntimeObservation, AnalysisError>>;
  close(): Promise<void>;
}
