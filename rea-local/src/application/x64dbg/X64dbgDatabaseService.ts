import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { X64dbgDatabasePort } from "./X64dbgDatabasePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  inspectX64dbgDatabaseInputSchema,
  X64DBG_VIEWS,
  x64dbgDatabaseSchema,
  type InspectX64dbgDatabaseInput,
  type X64dbgDatabaseReport,
} from "../../domain/x64dbg/x64dbgDatabase.js";

const OPERATION = "inspect_x64dbg_database";

/** The report must describe the selected database, module, view, filter and page. */
const matchesSelection = (
  report: X64dbgDatabaseReport,
  input: InspectX64dbgDatabaseInput,
): boolean => {
  const { page } = report;
  const rows = X64DBG_VIEWS.reduce((sum, view) => sum + report[view].length, 0);
  const module = input.module?.toLowerCase();
  const rowModules = X64DBG_VIEWS.flatMap((view) =>
    (report[view] as readonly object[]).map((row) =>
      "module" in row && typeof row.module === "string"
        ? row.module.toLowerCase()
        : null,
    ),
  );
  return (
    report.database.path === input.path &&
    (report.module_file?.path ?? null) === (input.module_path ?? null) &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.module === (input.module ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    (module === undefined || rowModules.every((name) => name === module))
  );
};

/** Shared x64dbg database validation and typed inline Evidence for CLI/MCP. */
export class X64dbgDatabaseService {
  constructor(readonly provider: X64dbgDatabasePort) {}

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
            inspectX64dbgDatabaseInputSchema,
            rawInput,
            (input) => [
              [["path"], input.path],
              [["module_path"], input.module_path],
            ],
          ),
        reportSchema: x64dbgDatabaseSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.database.path,
        reportSha256: (report) => report.database.sha256,
        malformedMessage:
          "x64dbg database reader returned malformed data, changed the selected database or module, or returned a different view or page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
