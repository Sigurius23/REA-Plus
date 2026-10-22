import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { GameMakerDataPort } from "./GameMakerDataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  GAMEMAKER_VIEWS,
  gameMakerDataSchema,
  inspectGameMakerDataInputSchema,
  type GameMakerDataReport,
  type InspectGameMakerDataInput,
} from "../../domain/gamemaker/gameMakerData.js";

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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parsePathInput(OPERATION, inspectGameMakerDataInputSchema, rawInput),
        reportSchema: gameMakerDataSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.file.path,
        reportSha256: (report) => report.file.sha256,
        malformedMessage:
          "GameMaker reader returned malformed data, changed the selected file identity or returned a different view or page than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
