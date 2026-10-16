import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { GodotFilePort } from "./GodotFilePort.js";
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
  DEFAULT_GODOT_VIEW,
  godotFileSchema,
  GODOT_VIEWS,
  inspectGodotFileInputSchema,
  type GodotFileReport,
  type InspectGodotFileInput,
} from "../../domain/godot/godotFile.js";

const OPERATION = "inspect_godot_file";

/** Rows of an owner-scoped view must all belong to the selected resource or node. */
const ownersHold = (
  report: GodotFileReport,
  input: InspectGodotFileInput,
): boolean =>
  report.properties.every(
    (row) =>
      (input.resource === undefined ||
        (row.owner_kind === "resource" && row.owner === input.resource)) &&
      (input.node === undefined ||
        (row.owner_kind === "node" && row.owner === input.node)),
  ) &&
  report.resources.every(
    ({ id }) => input.resource === undefined || id === input.resource,
  );

/** The report must describe the selected file, entry, view, selection and page. */
const matchesSelection = (
  report: GodotFileReport,
  input: InspectGodotFileInput,
): boolean => {
  const { page } = report;
  const rows = GODOT_VIEWS.reduce((sum, view) => sum + report[view].length, 0);
  return (
    report.file.path === input.path &&
    (report.entry === null) === (input.entry === undefined) &&
    page.view === (input.view ?? DEFAULT_GODOT_VIEW[report.kind]) &&
    page.resource === (input.resource ?? null) &&
    page.node === (input.node ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.returned === rows &&
    rows === report[page.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    ownersHold(report, input)
  );
};

/** Shared Godot file validation and typed inline Evidence for CLI/MCP. */
export class GodotFileService {
  constructor(readonly provider: GodotFilePort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectGodotFileInputSchema.safeParse(rawInput);
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
    const report = godotFileSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Godot file reader returned malformed data, changed the selected file or entry, or returned a different view, selection or page than requested.",
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
