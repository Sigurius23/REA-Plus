import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { DataBlobPort } from "./DataBlobPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  dataBlobSchema,
  inspectDataBlobInputSchema,
  type DataBlobReport,
  type InspectDataBlobInput,
} from "../../domain/blob/dataBlob.js";

const OPERATION = "inspect_data_blob";

/** The report must describe the selected file, byte range and format choice. */
const sourceHolds = (
  report: DataBlobReport,
  input: InspectDataBlobInput,
): boolean =>
  report.file.path === input.path &&
  report.range.offset === (input.range_offset ?? 0) &&
  (input.range_length === undefined ||
    report.range.length === input.range_length) &&
  report.format.forced === (input.format !== "auto") &&
  report.format.region_chunk === (input.region_chunk ?? null) &&
  (input.format === "auto" ||
    input.format === report.format.name ||
    input.region_chunk !== undefined);

/** The page must match the requested view, subtree, filters and bounds. */
const pageHolds = (
  report: DataBlobReport,
  input: InspectDataBlobInput,
): boolean => {
  const { page } = report;
  const rows = report.tree.length + report.strings.length;
  const base = input.node;
  return (
    page.view === input.view &&
    page.node === (base ?? null) &&
    page.max_depth === (input.max_depth ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    (base === undefined ||
      report.tree.every(({ path }) => path.startsWith(base)))
  );
};

const matchesSelection = (
  report: DataBlobReport,
  input: InspectDataBlobInput,
): boolean => sourceHolds(report, input) && pageHolds(report, input);

/** Shared data blob validation and typed inline Evidence for CLI/MCP. */
export class DataBlobService {
  constructor(readonly provider: DataBlobPort) {}

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
          parsePathInput(OPERATION, inspectDataBlobInputSchema, rawInput),
        reportSchema: dataBlobSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.file.path,
        reportSha256: (report) => report.file.sha256,
        malformedMessage:
          "Data blob reader returned malformed data, changed the selected file or range, or returned a different format, view, subtree or page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
