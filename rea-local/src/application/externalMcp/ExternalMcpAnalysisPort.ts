import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ExternalMcpRequest } from "../../domain/externalMcp/externalMcpAnalysis.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { Result } from "../../domain/result.js";

/** Stable identity reported by the configured upstream MCP server. */
export interface ExternalMcpProviderIdentity {
  readonly id: string;
  readonly name: string;
  readonly version: string | null;
}

/** One bounded upstream response before REA+ adds its Evidence envelope. */
export interface ExternalMcpObservation {
  readonly result: JsonValue;
  readonly provider: ExternalMcpProviderIdentity;
  readonly limitations: readonly string[];
}

/** Cancellation context for one external MCP request. */
export interface ExternalMcpExecutionOptions {
  readonly signal?: AbortSignal;
}

/** Configured upstream MCP execution plus its owned transport lifetime. */
export interface ExternalMcpAnalysisPort {
  execute(
    request: ExternalMcpRequest,
    options?: ExternalMcpExecutionOptions,
  ): Promise<Result<ExternalMcpObservation, AnalysisError>>;
  close(): Promise<void>;
}
