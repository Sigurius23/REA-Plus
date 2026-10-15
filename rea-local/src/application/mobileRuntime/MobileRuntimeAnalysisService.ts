import { createHash } from "node:crypto";
import { z } from "zod";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  mobileRuntimeInputSchemas,
  mobileRuntimeRequestSchema,
  mobileRuntimeResultSchemas,
  type MobileRuntimeOperation,
  type MobileRuntimeRequest,
} from "../../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import { jsonObjectSchema, jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { MobileRuntimeAnalysisPort } from "./MobileRuntimeAnalysisPort.js";

/**
 * Shared MCP/Evidence boundary for optional runtime-instrumentation providers.
 * Raw Frida scripts and Objection commands are deliberately never copied into
 * Evidence parameters; only their byte lengths and SHA-256 commitments are.
 */
export class MobileRuntimeAnalysisService {
  constructor(readonly provider: MobileRuntimeAnalysisPort) {}

  async execute(
    operation: MobileRuntimeOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));

    const parsed = mobileRuntimeRequestSchema.safeParse({ operation, input });
    if (!parsed.success)
      return err(new AnalysisInputError(operation, { cause: parsed.error }));

    const request = parsed.data as MobileRuntimeRequest;
    const executed = await this.provider.execute(request, options);
    if (!executed.ok) return executed;

    const resultSchema = mobileRuntimeResultSchemas[operation];
    const result = resultSchema.safeParse(executed.value.result);
    if (!result.success)
      return err(
        new AnalysisOutputError(
          operation,
          "provider result did not match its public schema",
          {
            cause: result.error,
          },
        ),
      );

    const parameters = evidenceParameters(operation, request.input);

    try {
      return ok(
        createEvidence(undefined, executed.value.provider, {
          operation,
          predicateType: `runtime.instrumentation.${operation}`,
          parameters: jsonObjectSchema.parse(parameters),
          result: jsonValueSchema.parse(result.data),
          confidence: "observed",
          authority: "external-service",
          limitations: [
            ...executed.value.limitations,
            "Runtime observations are not bound to an REA+ artifact identity unless that association is independently established.",
          ],
          subjectUnavailableReason:
            "The selected runtime process or device was not bound to a specific REA+ artifact identity.",
        }),
      );
    } catch (cause) {
      return err(
        new AnalysisOutputError(operation, "could not construct Evidence", {
          cause,
        }),
      );
    }
  }
}

const evidenceParameters = (
  operation: MobileRuntimeOperation,
  input: MobileRuntimeRequest["input"],
): Readonly<Record<string, unknown>> => {
  if (operation === "list_frida_devices") return {};
  if (operation === "list_frida_processes") {
    const typed = input as z.infer<
      typeof mobileRuntimeInputSchemas.list_frida_processes
    >;
    return { device_id: typed.device_id ?? null };
  }
  if (operation === "run_frida_script") {
    const typed = input as z.infer<
      typeof mobileRuntimeInputSchemas.run_frida_script
    >;
    return {
      device_id: typed.device_id ?? null,
      pid: typed.pid,
      script_sha256: `sha256:${createHash("sha256").update(typed.script).digest("hex")}`,
      script_bytes: Buffer.byteLength(typed.script, "utf8"),
      observation_ms: typed.observation_ms,
      runtime_code_execution_confirmed: true,
    };
  }
  const typed = input as z.infer<
    typeof mobileRuntimeInputSchemas.run_objection_command
  >;
  return {
    target: typed.target,
    device_serial: typed.device_serial ?? null,
    command_sha256: `sha256:${createHash("sha256").update(typed.command).digest("hex")}`,
    command_bytes: Buffer.byteLength(typed.command, "utf8"),
    timeout_ms: typed.timeout_ms,
    runtime_command_execution_confirmed: true,
  };
};
