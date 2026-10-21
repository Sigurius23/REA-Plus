import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { X64dbgDatabasePort } from "./X64dbgDatabasePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parseInputWithAbsolutePaths(
      OPERATION,
      inspectX64dbgDatabaseInputSchema,
      rawInput,
      (input) => [
        [["path"], input.path],
        [["module_path"], input.module_path],
      ],
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = x64dbgDatabaseSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.database.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "x64dbg database reader returned malformed data, changed the selected database or module, or returned a different view or page than requested.",
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
