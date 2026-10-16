import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { GameArchivePort } from "./GameArchivePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  gameArchiveSchema,
  inspectGameArchiveInputSchema,
  type GameArchive,
  type InspectGameArchiveInput,
} from "../../domain/gamearchives/gameArchive.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
    const input = inspectGameArchiveInputSchema.safeParse(rawInput);
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
    const report = gameArchiveSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.archive.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Game archive reader returned malformed data, changed the selected archive identity or returned a different page or entry than requested.",
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
