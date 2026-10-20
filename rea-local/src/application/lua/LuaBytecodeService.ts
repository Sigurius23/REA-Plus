import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { LuaBytecodePort } from "./LuaBytecodePort.js";
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
    const input = inspectLuaBytecodeInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = luaBytecodeSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Lua bytecode reader returned malformed data, changed the selected file or chunk, or returned a different view, function or page than requested.",
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
