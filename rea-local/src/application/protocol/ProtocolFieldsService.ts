import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { ProtocolFieldsPort } from "./ProtocolFieldsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parsePathInput(OPERATION, inferProtocolFieldsInputSchema, rawInput),
        reportSchema: protocolFieldsSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.file.path,
        reportSha256: (report) => report.file.sha256,
        malformedMessage:
          "Protocol inference returned malformed data, changed the selected file, or returned a different view, format or page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
