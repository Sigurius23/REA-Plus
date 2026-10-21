import { z } from "zod";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput } from "../InlineReportService.js";
import type { EvmInterfacePort } from "./EvmInterfacePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectEvmInterfaceInputSchema,
  evmInterfaceSchema,
} from "../../domain/evm/evmInterface.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_evm_interface";
const diagnosticsSchema = z.object({
  diagnostics: evmInterfaceSchema.shape.diagnostics,
});

/** Shared carrier validation and typed inline Evidence for CLI/MCP. */
export class EvmInterfaceService {
  constructor(readonly provider: EvmInterfacePort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Preserve selected byte identity while clearly labeling recovered ABI candidates as inferences. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectEvmInterfaceInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    const diagnostics = diagnosticsSchema.safeParse(inspected.value.result);
    const outputOptions = diagnostics.success
      ? { capturedOutput: diagnostics.data.diagnostics }
      : undefined;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION, outputOptions));
    const execution = inspected.value;
    const report = evmInterfaceSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.artifact.path !== input.value.path ||
      report.data.artifact.encoding !== input.value.encoding ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.artifact.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Interface adapter returned malformed data or changed the selected carrier identity/encoding.",
          outputOptions,
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: input.value,
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "inferred",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
