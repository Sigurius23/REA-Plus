import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { LogicCapturePort } from "./LogicCapturePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
    const input = inspectLogicCaptureInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = logicCaptureSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.capture.path !== input.data.path ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.capture.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Logic-capture reader returned malformed data, changed the selected capture identity or returned more annotations than requested.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: Object.fromEntries(
          Object.entries(input.data).filter(([, value]) => value !== undefined),
        ) as Readonly<Record<string, JsonValue>>,
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "observed",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
