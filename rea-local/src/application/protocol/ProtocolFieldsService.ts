import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { ProtocolFieldsPort } from "./ProtocolFieldsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  inferProtocolFieldsInputSchema,
  protocolFieldsSchema,
  PROTOCOL_VIEWS,
  type InferProtocolFieldsInput,
  type ProtocolFieldsReport,
} from "../../domain/protocol/protocolFields.js";

const OPERATION = "infer_protocol_fields";

/** The report must describe the selected file, view, format and page. */
const matchesSelection = (
  report: ProtocolFieldsReport,
  input: InferProtocolFieldsInput,
): boolean => {
  const { page } = report;
  const rows = PROTOCOL_VIEWS.reduce(
    (sum, view) => sum + report[view].length,
    0,
  );
  const formatHolds =
    input.format === undefined ||
    input.view === "flows" ||
    (input.view === "formats"
      ? report.formats.every(({ id }) => id === input.format)
      : report[input.view].every(({ format }) => format === input.format));
  return (
    report.file.path === input.path &&
    page.view === input.view &&
    page.format === (input.format ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    formatHolds
  );
};

/** Shared protocol inference validation and typed inline Evidence for CLI/MCP. */
export class ProtocolFieldsService {
  constructor(readonly provider: ProtocolFieldsPort) {}

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
      inferProtocolFieldsInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = protocolFieldsSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Protocol inference returned malformed data, changed the selected file, or returned a different view, format or page than requested.",
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
