import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { GameMakerDataPort } from "./GameMakerDataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
    const input = inspectGameMakerDataInputSchema.safeParse(rawInput);
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
    const report = gameMakerDataSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "GameMaker reader returned malformed data, changed the selected file identity or returned a different view or page than requested.",
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
