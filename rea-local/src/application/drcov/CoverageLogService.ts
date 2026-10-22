import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { CoverageLogPort } from "./CoverageLogPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  coverageLogSchema,
  inspectCoverageLogInputSchema,
  type CoverageLog,
  type InspectCoverageLogInput,
} from "../../domain/drcov/coverageLog.js";

const OPERATION = "inspect_coverage_log";

/** The report must describe exactly the selected logs and requested page. */
const matchesSelection = (
  report: CoverageLog,
  input: InspectCoverageLogInput,
): boolean => {
  const { page } = report;
  return (
    report.log.path === input.path &&
    (report.baseline?.path ?? null) === (input.baseline_path ?? null) &&
    (report.selected_module === null) === (input.module === undefined) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.returned === report.blocks.length &&
    page.returned ===
      Math.max(0, Math.min(input.limit, page.total - input.offset))
  );
};

/** Shared coverage-log validation and typed inline Evidence for CLI/MCP. */
export class CoverageLogService {
  constructor(readonly provider: CoverageLogPort) {}

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
            inspectCoverageLogInputSchema,
            rawInput,
            (input) => [
              [["path"], input.path],
              [["baseline_path"], input.baseline_path],
            ],
          ),
        reportSchema: coverageLogSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.log.path,
        reportSha256: (report) => report.log.sha256,
        malformedMessage:
          "Coverage reader returned malformed data, changed a selected log identity or returned a different page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
