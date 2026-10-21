import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { BinaryDiffPort } from "./BinaryDiffPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parseInputWithAbsolutePaths(
      OPERATION,
      diffBinariesInputSchema,
      rawInput,
      (input) => [
        [["left"], input.left],
        [["right"], input.right],
      ],
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = binaryDiffSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.right ||
      execution.subject.sha256 !== report.data.right.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Binary diffing returned malformed data, changed the selected builds, or returned a different view or page than requested.",
        ),
      );
    return ok(
      inlineReportEvidence(
        OPERATION,
        execution,
        input.value,
        report.data,
        "inferred",
      ),
    );
  }
}
