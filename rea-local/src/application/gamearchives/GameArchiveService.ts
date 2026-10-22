import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { GameArchivePort } from "./GameArchivePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  gameArchiveSchema,
  inspectGameArchiveInputSchema,
  type GameArchive,
  type InspectGameArchiveInput,
} from "../../domain/gamearchives/gameArchive.js";

const OPERATION = "inspect_game_archive";

/** The report must describe the selected archive, page and entry. */
const matchesSelection = (
  report: GameArchive,
  input: InspectGameArchiveInput,
): boolean => {
  const { page, entry } = report;
  return (
    report.archive.path === input.path &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.extension === (input.extension ?? null) &&
    page.returned === report.entries.length &&
    report.entries.length <= input.limit &&
    report.entries.length <= Math.max(0, page.total - input.offset) &&
    (input.entry === undefined
      ? entry === null
      : entry !== null &&
        (entry.preview === null ||
          (entry.encoding === "hex"
            ? entry.preview.length <= input.preview_bytes * 2
            : Buffer.byteLength(entry.preview) <= input.preview_bytes)))
  );
};

/** Shared game archive validation and typed inline Evidence for CLI/MCP. */
export class GameArchiveService {
  constructor(readonly provider: GameArchivePort) {}

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
          parsePathInput(OPERATION, inspectGameArchiveInputSchema, rawInput),
        reportSchema: gameArchiveSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.archive.path,
        reportSha256: (report) => report.archive.sha256,
        malformedMessage:
          "Game archive reader returned malformed data, changed the selected archive identity or returned a different page or entry than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
