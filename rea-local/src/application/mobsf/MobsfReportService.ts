import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { MobsfReportPort } from "./MobsfReportPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parseInputWithAbsolutePaths(
            OPERATION,
            inspectMobsfReportInputSchema,
            rawInput,
            (input) => [
              [["path"], input.path],
              [["app_path"], input.app_path],
            ],
          ),
        reportSchema: mobsfReportSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.report.path,
        reportSha256: (report) => report.report.sha256,
        malformedMessage:
          "MobSF report reader returned malformed data, changed the selected report identity or returned a different view, filter or page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
