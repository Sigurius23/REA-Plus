import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { LogicCapturePort } from "./LogicCapturePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  inspectLogicCaptureInputSchema,
  logicCaptureSchema,
  type InspectLogicCaptureInput,
  type LogicCapture,
} from "../../domain/logic/logicCapture.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_logic_capture";

/** The report must describe the selected capture and honour the decode request. */
const matchesSelection = (
  report: LogicCapture,
  input: InspectLogicCaptureInput,
): boolean => {
  const { decode } = report;
  if (decode === null) return input.decoders === undefined;
  return (
    input.decoders !== undefined &&
    decode.totals.every(({ returned }) => returned <= input.annotation_limit) &&
    decode.annotations.length ===
      decode.totals.reduce((sum, { returned }) => sum + returned, 0) &&
    (input.annotations === undefined ||
      decode.totals.map(({ class: name }) => name).join() ===
        input.annotations.join())
  );
};

/** Shared logic-capture validation and typed inline Evidence for CLI/MCP. */
export class LogicCaptureService {
  constructor(readonly provider: LogicCapturePort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectLogicCaptureInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = logicCaptureSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.capture.path !== input.value.path ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.capture.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Logic-capture reader returned malformed data, changed the selected capture identity or returned more annotations than requested.",
        ),
      );
    return ok(
      inlineReportEvidence(
        OPERATION,
        execution,
        input.value,
        report.data,
        "observed",
      ),
    );
  }
}
