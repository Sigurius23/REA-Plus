import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { UnityAssetsPort } from "./UnityAssetsPort.js";
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
  inspectUnityAssetsInputSchema,
  unityAssetsSchema,
  type InspectUnityAssetsInput,
  type UnityAssets,
} from "../../domain/unity/unityAssets.js";

const OPERATION = "inspect_unity_assets";

/** The report must describe the selected file and the requested page. */
const matchesSelection = (
  report: UnityAssets,
  input: InspectUnityAssetsInput,
): boolean => {
  const { page } = report;
  const rows =
    report.objects.length + report.container.length + report.scripts.length;
  const viewRows =
    input.view === "objects"
      ? report.objects.length
      : input.view === "container"
        ? report.container.length
        : report.scripts.length;
  return (
    report.file.path === input.path &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.class_name === (input.class_name ?? null) &&
    page.returned === rows &&
    rows === viewRows &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset)
  );
};

/** Shared Unity asset validation and typed inline Evidence for CLI/MCP. */
export class UnityAssetsService {
  constructor(readonly provider: UnityAssetsPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectUnityAssetsInputSchema.safeParse(rawInput);
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
    const report = unityAssetsSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Unity asset reader returned malformed data, changed the selected file identity or returned a different page than requested.",
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
