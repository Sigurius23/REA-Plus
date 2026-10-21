import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { LuaBytecodePort } from "./LuaBytecodePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  inspectLuaBytecodeInputSchema,
  LUA_VIEWS,
  luaBytecodeSchema,
  type InspectLuaBytecodeInput,
  type LuaBytecodeReport,
} from "../../domain/lua/luaBytecode.js";

const OPERATION = "inspect_lua_bytecode";

/** Rows of a function-scoped view must all belong to the selected function. */
const functionHolds = (
  report: LuaBytecodeReport,
  selected: string | undefined,
): boolean =>
  selected === undefined ||
  (report.functions.every(({ id }) => id === selected) &&
    [
      report.instructions,
      report.constants,
      report.locals,
      report.upvalues,
    ].every((rows) => rows.every((row) => row.function === selected)));

/** The report must describe the selected file, chunk offset, view, function and page. */
const matchesSelection = (
  report: LuaBytecodeReport,
  input: InspectLuaBytecodeInput,
): boolean => {
  const { page } = report;
  const rows = LUA_VIEWS.reduce((sum, view) => sum + report[view].length, 0);
  return (
    report.file.path === input.path &&
    (report.chunk === null
      ? input.view === "chunks"
      : report.chunk.offset === (input.chunk_offset ?? 0)) &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.function === (input.function ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    functionHolds(report, input.function)
  );
};

/** Shared Lua bytecode validation and typed inline Evidence for CLI/MCP. */
export class LuaBytecodeService {
  constructor(readonly provider: LuaBytecodePort) {}

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
      inspectLuaBytecodeInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = luaBytecodeSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Lua bytecode reader returned malformed data, changed the selected file or chunk, or returned a different view, function or page than requested.",
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
