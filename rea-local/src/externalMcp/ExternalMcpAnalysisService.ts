import type { ExternalMcpExecutionOptions } from "../application/externalMcp/ExternalMcpAnalysisPort.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import {
  externalMcpRequestSchema,
  type ExternalMcpOperation,
} from "../domain/externalMcp/externalMcpAnalysis.js";
import { jsonObjectSchema, jsonValueSchema } from "../domain/jsonValue.js";
import type { Result } from "../domain/result.js";
import type { ExternalMcpAnalysisPort } from "../application/externalMcp/ExternalMcpAnalysisPort.js";

/** Turn configured upstream operations into provenance-bearing REA+ Evidence. */
export class ExternalMcpAnalysisService {
  constructor(private readonly provider: ExternalMcpAnalysisPort) {}

  async execute(
    operation: ExternalMcpOperation,
    input: unknown,
    options?: ExternalMcpExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return {
        ok: false,
        error: new AnalysisCancelledError(operation),
      };

    const parsed = externalMcpRequestSchema.safeParse({ operation, input });
    if (!parsed.success)
      return {
        ok: false,
        error: new AnalysisInputError(operation, { cause: parsed.error }),
      };

    const execution = await this.provider.execute(parsed.data, options);
    if (!execution.ok) return execution;

    const request = parsed.data;
    const parameters =
      request.operation === "call_external_mcp_tool"
        ? {
            server_id: request.input.server_id,
            tool_name: request.input.tool_name,
            arguments_sha256: `sha256:${digestCanonicalValue(
              request.input.arguments,
              "External MCP arguments",
            )}`,
            arguments_bytes: Buffer.byteLength(
              JSON.stringify(request.input.arguments) ?? "",
            ),
          }
        : request.input;

    return {
      ok: true,
      value: createEvidence(undefined, execution.value.provider, {
        operation: request.operation,
        predicateType: "rea.external-mcp",
        parameters: jsonObjectSchema.parse(parameters),
        result: jsonValueSchema.parse(execution.value.result),
        rawResult: null,
        confidence: "observed",
        authority: "external-service",
        limitations: execution.value.limitations,
        subjectUnavailableReason:
          "The upstream MCP server's internal analysis target is not independently bound to an REA+-opened artifact.",
      }),
    };
  }
}
