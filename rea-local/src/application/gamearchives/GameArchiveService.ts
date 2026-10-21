import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { GameArchivePort } from "./GameArchivePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  gameArchiveSchema,
  inspectGameArchiveInputSchema,
  type GameArchive,
  type InspectGameArchiveInput,
} from "../../domain/gamearchives/gameArchive.js";
import { err, ok, type Result } from "../../domain/result.js";

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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectGameArchiveInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = gameArchiveSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.archive.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Game archive reader returned malformed data, changed the selected archive identity or returned a different page or entry than requested.",
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
