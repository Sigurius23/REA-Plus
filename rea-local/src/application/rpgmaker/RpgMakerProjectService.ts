import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { RpgMakerProjectPort } from "./RpgMakerProjectPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  inspectRpgMakerProjectInputSchema,
  rpgMakerProjectSchema,
  type InspectRpgMakerProjectInput,
  type RpgMakerProjectReport,
} from "../../domain/rpgmaker/rpgMakerProject.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_rpgmaker_project";

type View = InspectRpgMakerProjectInput["view"];
const VIEWS = [
  "maps",
  "dialogue",
  "switches",
  "database",
  "plugins",
  "assets",
  "saves",
] as const satisfies readonly View[];

/** Filters the caller selected must hold for every returned row. */
const filtersHold = (
  report: RpgMakerProjectReport,
  input: InspectRpgMakerProjectInput,
): boolean => {
  const { map, table } = input;
  const inMap = (row: { source: string; source_id: number }) =>
    row.source === "map" && row.source_id === map;
  return (
    (map === undefined ||
      (report.maps.every((row) => row.id === map) &&
        report.dialogue.every(inMap) &&
        report.switches.every((row) => row.sites.every(inMap)))) &&
    (table === undefined ||
      report.database.every((row) => row.table === table)) &&
    (input.asset === undefined
      ? report.page.asset === null
      : report.page.asset !== null &&
        report.assets.length <= 1 &&
        report.assets.every((row) => row.path === report.page.asset))
  );
};

/** The report must describe the selected folder, view, filters and page. */
const matchesSelection = (
  report: RpgMakerProjectReport,
  input: InspectRpgMakerProjectInput,
): boolean => {
  const { page } = report;
  const counts = VIEWS.map((view) => report[view].length);
  const rows = counts.reduce((sum, value) => sum + value, 0);
  return (
    report.project.path === input.path &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.map === (input.map ?? null) &&
    page.table === (input.table ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    filtersHold(report, input)
  );
};

/** Shared RPG Maker project validation and typed inline Evidence for CLI/MCP. */
export class RpgMakerProjectService {
  constructor(readonly provider: RpgMakerProjectPort) {}

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
      inspectRpgMakerProjectInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    if (
      input.value.asset !== undefined &&
      (isAbsolute(input.value.asset) ||
        input.value.asset.split(/[\\/]/u).includes(".."))
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["asset"],
            reason: "invalid_format",
            message:
              "Expected a path relative to the game folder, without '..'.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = rpgMakerProjectSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.project.data_sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "RPG Maker reader returned malformed data, changed the selected game identity or returned a different view, filter or page than requested.",
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
