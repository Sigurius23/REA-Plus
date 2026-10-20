import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { X64dbgDatabasePort } from "./X64dbgDatabasePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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

const absolute = (field: "path" | "module_path"): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    {
      path: [field],
      reason: "invalid_format",
      message: "Expected an absolute filesystem path on this host.",
    },
  ]);

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
    const input = inspectX64dbgDatabaseInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path)) return err(absolute("path"));
    if (
      input.data.module_path !== undefined &&
      !isAbsolute(input.data.module_path)
    )
      return err(absolute("module_path"));
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = x64dbgDatabaseSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.database.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "x64dbg database reader returned malformed data, changed the selected database or module, or returned a different view or page than requested.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: Object.fromEntries(
          Object.entries(input.data).filter(([, value]) => value !== undefined),
        ) as Readonly<Record<string, JsonValue>>,
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "observed",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
