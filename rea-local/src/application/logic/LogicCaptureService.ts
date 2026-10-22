import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { LogicCapturePort } from "./LogicCapturePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  inspectLogicCaptureInputSchema,
  logicCaptureSchema,
  type InspectLogicCaptureInput,
  type LogicCapture,
} from "../../domain/logic/logicCapture.js";

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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parsePathInput(OPERATION, inspectLogicCaptureInputSchema, rawInput),
        reportSchema: logicCaptureSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.capture.path,
        reportSha256: (report) => report.capture.sha256,
        malformedMessage:
          "Logic-capture reader returned malformed data, changed the selected capture identity or returned more annotations than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
