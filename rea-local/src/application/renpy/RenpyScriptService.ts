import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { RenpyScriptPort } from "./RenpyScriptPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  inspectRenpyScriptInputSchema,
  renpyScriptSchema,
  type InspectRenpyScriptInput,
  type RenpyScriptReport,
} from "../../domain/renpy/renpyScript.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_renpy_script";

const VIEW_ROWS: Readonly<
  Record<InspectRenpyScriptInput["view"], (report: RenpyScriptReport) => number>
> = {
  labels: (report) => report.labels.length,
  dialogue: (report) => report.dialogue.length,
  menus: (report) => report.menus.length,
  definitions: (report) => report.definitions.length,
  translations: (report) => report.translations.length,
};

/** The report must describe the selected script, view, filters and page. */
const matchesSelection = (
  report: RenpyScriptReport,
  input: InspectRenpyScriptInput,
): boolean => {
  const { page } = report;
  const rows = Object.values(VIEW_ROWS).reduce(
    (sum, rowsOf) => sum + rowsOf(report),
    0,
  );
  return (
    report.script.path === input.path &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.label === (input.label ?? null) &&
    page.returned === rows &&
    rows === VIEW_ROWS[input.view](report) &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    (input.label === undefined ||
      [...report.dialogue, ...report.menus].every(
        (row) => row.label === input.label,
      ))
  );
};

/** Shared Ren'Py script validation and typed inline Evidence for CLI/MCP. */
export class RenpyScriptService {
  constructor(readonly provider: RenpyScriptPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectRenpyScriptInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = renpyScriptSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.script.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Ren'Py script reader returned malformed data, changed the selected script identity or returned a different view or page than requested.",
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
