import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { CoverageLogPort } from "./CoverageLogPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  coverageLogSchema,
  inspectCoverageLogInputSchema,
  type CoverageLog,
  type InspectCoverageLogInput,
} from "../../domain/drcov/coverageLog.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_coverage_log";

/** The report must describe exactly the selected logs and requested page. */
const matchesSelection = (
  report: CoverageLog,
  input: InspectCoverageLogInput,
): boolean => {
  const { page } = report;
  return (
    report.log.path === input.path &&
    (report.baseline?.path ?? null) === (input.baseline_path ?? null) &&
    (report.selected_module === null) === (input.module === undefined) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.returned === report.blocks.length &&
    page.returned ===
      Math.max(0, Math.min(input.limit, page.total - input.offset))
  );
};

/** Shared coverage-log validation and typed inline Evidence for CLI/MCP. */
export class CoverageLogService {
  constructor(readonly provider: CoverageLogPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectCoverageLogInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = (["path", "baseline_path"] as const).filter((field) => {
      const value = input.data[field];
      return value !== undefined && !isAbsolute(value);
    });
    if (relative.length > 0)
      return err(
        new AnalysisInputError(
          OPERATION,
          undefined,
          relative.map((field) => ({
            path: [field],
            reason: "invalid_format" as const,
            message: "Expected an absolute filesystem path on this host.",
          })),
        ),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = coverageLogSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.log.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Coverage reader returned malformed data, changed a selected log identity or returned a different page than requested.",
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
