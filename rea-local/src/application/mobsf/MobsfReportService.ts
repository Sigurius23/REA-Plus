import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { MobsfReportPort } from "./MobsfReportPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  inspectMobsfReportInputSchema,
  MOBSF_VIEWS,
  mobsfReportSchema,
  type InspectMobsfReportInput,
  type MobsfReport,
} from "../../domain/mobsf/mobsfReport.js";

const OPERATION = "inspect_mobsf_report";

/** Every returned finding or location satisfies the severity and section filters. */
const filtersHold = (
  report: MobsfReport,
  input: InspectMobsfReportInput,
): boolean => {
  const sectioned: readonly { readonly section: string }[] =
    input.view === "locations" ? report.locations : report.findings;
  return (
    (input.severity === undefined ||
      report.findings.every(({ severity }) => severity === input.severity)) &&
    (input.section === undefined ||
      sectioned.every(({ section }) => section === input.section))
  );
};

/** The report must describe the selected report, app file, view, filters and page. */
const matchesSelection = (
  report: MobsfReport,
  input: InspectMobsfReportInput,
): boolean => {
  const { page } = report;
  const rows = MOBSF_VIEWS.reduce((sum, view) => sum + report[view].length, 0);
  return (
    report.report.path === input.path &&
    (report.app_file?.path ?? null) === (input.app_path ?? null) &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.severity === (input.severity ?? null) &&
    page.section === (input.section ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    filtersHold(report, input)
  );
};

/** Shared MobSF report validation and typed inline Evidence for CLI/MCP. */
export class MobsfReportService {
  constructor(readonly provider: MobsfReportPort) {}

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
      inspectMobsfReportInputSchema,
      rawInput,
      (input) => [
        [["path"], input.path],
        [["app_path"], input.app_path],
      ],
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = mobsfReportSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.report.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "MobSF report reader returned malformed data, changed the selected report identity or returned a different view, filter or page than requested.",
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
