import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { GameMakerDataPort } from "./GameMakerDataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  GAMEMAKER_VIEWS,
  gameMakerDataSchema,
  inspectGameMakerDataInputSchema,
  type GameMakerDataReport,
  type InspectGameMakerDataInput,
} from "../../domain/gamemaker/gameMakerData.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_gamemaker_data";

/** The report must describe the selected file, view, kind filter and page. */
const matchesSelection = (
  report: GameMakerDataReport,
  input: InspectGameMakerDataInput,
): boolean => {
  const { page } = report;
  const rows = GAMEMAKER_VIEWS.reduce(
    (sum, view) => sum + report[view].length,
    0,
  );
  return (
    report.file.path === input.path &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.kind === (input.kind ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    (input.kind === undefined ||
      report.resources.every((row) => row.kind === input.kind))
  );
};

/** Shared GameMaker data validation and typed inline Evidence for CLI/MCP. */
export class GameMakerDataService {
  constructor(readonly provider: GameMakerDataPort) {}

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
      inspectGameMakerDataInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = gameMakerDataSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "GameMaker reader returned malformed data, changed the selected file identity or returned a different view or page than requested.",
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
