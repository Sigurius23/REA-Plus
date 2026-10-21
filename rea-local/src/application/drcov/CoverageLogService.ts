import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { CoverageLogPort } from "./CoverageLogPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  coverageLogSchema,
  inspectCoverageLogInputSchema,
  type CoverageLog,
  type InspectCoverageLogInput,
} from "../../domain/drcov/coverageLog.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";

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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parseInputWithAbsolutePaths(
      OPERATION,
      inspectCoverageLogInputSchema,
      rawInput,
      (input) => [
        [["path"], input.path],
        [["baseline_path"], input.baseline_path],
      ],
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = coverageLogSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.log.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Coverage reader returned malformed data, changed a selected log identity or returned a different page than requested.",
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
