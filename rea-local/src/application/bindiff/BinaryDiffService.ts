import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  inspectInlineReport,
  parseInputWithAbsolutePaths,
} from "../InlineReportService.js";
import type { BinaryDiffPort } from "./BinaryDiffPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  binaryDiffSchema,
  diffBinariesInputSchema,
  type BinaryDiffReport,
  type DiffBinariesInput,
} from "../../domain/bindiff/binaryDiff.js";

const OPERATION = "diff_binaries";

/** Rows of the selected view, and only those, carry the selected status. */
const rowsFitView = (report: BinaryDiffReport, input: DiffBinariesInput) => {
  const { view, status } = input;
  if (view === "function")
    return report.functions.length + report.unmatched.length <= 1;
  if (view === "unmatched")
    return (
      report.functions.length === 0 &&
      (status === undefined ||
        report.unmatched.every((row) => row.status === status))
    );
  return (
    report.unmatched.length === 0 &&
    (view === "summary" ||
      status === undefined ||
      report.functions.every((row) => row.status === status))
  );
};

/** The report must describe the selected builds, view and page. */
const matchesSelection = (
  report: BinaryDiffReport,
  input: DiffBinariesInput,
): boolean => {
  const { page } = report;
  const rows = report.functions.length + report.unmatched.length;
  return (
    report.left.path === input.left &&
    report.right.path === input.right &&
    page.view === input.view &&
    page.status === (input.status ?? null) &&
    page.function === (input.function ?? null) &&
    page.query === (input.query ?? null) &&
    page.limit === input.limit &&
    page.returned === rows &&
    rows <= input.limit &&
    (input.view === "function" || page.offset === input.offset) &&
    rowsFitView(report, input)
  );
};

/** Shared binary diff validation and typed inline Evidence for CLI/MCP. */
export class BinaryDiffService {
  constructor(readonly provider: BinaryDiffPort) {}

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
          parseInputWithAbsolutePaths(
            OPERATION,
            diffBinariesInputSchema,
            rawInput,
            (input) => [
              [["left"], input.left],
              [["right"], input.right],
            ],
          ),
        reportSchema: binaryDiffSchema,
        matchesSelection,
        inputPath: ({ right }) => right,
        reportPath: (report) => report.right.path,
        reportSha256: (report) => report.right.sha256,
        malformedMessage:
          "Binary diffing returned malformed data, changed the selected builds, or returned a different view or page than requested.",
        confidence: "inferred",
      },
      async (input, signal) => this.provider.inspect(input, signal),
      rawInput,
      options,
    );
  }
}
