import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { BinaryDiffPort } from "./BinaryDiffPort.js";
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
  binaryDiffSchema,
  diffBinariesInputSchema,
  type BinaryDiffReport,
  type DiffBinariesInput,
} from "../../domain/bindiff/binaryDiff.js";

const OPERATION = "diff_binaries";

/** Rows of the selected view, and only those, carry the selected status. */
const rowsFitView = (report: BinaryDiffReport, input: DiffBinariesInput) => {
  const { view, status } = input;
  if (view === "function")
    return report.functions.length + report.unmatched.length <= 1;
  if (view === "unmatched")
    return (
      report.functions.length === 0 &&
      (status === undefined ||
        report.unmatched.every((row) => row.status === status))
    );
  return (
    report.unmatched.length === 0 &&
    (view === "summary" ||
      status === undefined ||
      report.functions.every((row) => row.status === status))
  );
};

/** The report must describe the selected builds, view and page. */
const matchesSelection = (
  report: BinaryDiffReport,
  input: DiffBinariesInput,
): boolean => {
  const { page } = report;
  const rows = report.functions.length + report.unmatched.length;
  return (
    report.left.path === input.left &&
    report.right.path === input.right &&
    page.view === input.view &&
    page.status === (input.status ?? null) &&
    page.function === (input.function ?? null) &&
    page.query === (input.query ?? null) &&
    page.limit === input.limit &&
    page.returned === rows &&
    rows <= input.limit &&
    (input.view === "function" || page.offset === input.offset) &&
    rowsFitView(report, input)
  );
};

/** Shared binary diff validation and typed inline Evidence for CLI/MCP. */
export class BinaryDiffService {
  constructor(readonly provider: BinaryDiffPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = diffBinariesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    for (const side of ["left", "right"] as const)
      if (!isAbsolute(input.data[side]))
        return err(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: [side],
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
    const report = binaryDiffSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.right ||
      execution.subject.sha256 !== report.data.right.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Binary diffing returned malformed data, changed the selected builds, or returned a different view or page than requested.",
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
        confidence: "inferred",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
