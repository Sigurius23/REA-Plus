import { isAbsolute } from "node:path";
import type { z } from "zod";

import type {
  AnalysisExecution,
  ExecutionOptions,
} from "./AnalysisProvider.js";
import {
  AnalysisInputError,
  AnalysisCancelledError,
  AnalysisOutputError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceObservation,
} from "../domain/evidence.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";

/** One caller-supplied filesystem path and where it sits in the input. */
export type InputPathField = readonly [
  path: AnalysisInputIssue["path"],
  value: string | undefined,
];

/**
 * Parse CLI/MCP input and require host-absolute paths at the given fields.
 *
 * Shared by the offline inspectors whose providers read caller-selected files;
 * a relative path would resolve against the server's working directory.
 */
export const parseInputWithAbsolutePaths = <T>(
  operation: string,
  schema: z.ZodType<T>,
  rawInput: unknown,
  pathsOf: (input: T) => Iterable<InputPathField>,
): Result<T, AnalysisInputError> => {
  const input = schema.safeParse(rawInput);
  if (!input.success)
    return err(
      analysisInputErrorFromIssues(operation, input.error.issues, rawInput, {
        cause: input.error,
      }),
    );
  const relative = [...pathsOf(input.data)].filter(
    ([, value]) => value !== undefined && !isAbsolute(value),
  );
  if (relative.length > 0)
    return err(
      new AnalysisInputError(
        operation,
        undefined,
        relative.map(([path]) => ({
          path,
          reason: "invalid_format" as const,
          message: "Expected an absolute filesystem path on this host.",
        })),
      ),
    );
  return ok(input.data);
};

/** Parse input whose only filesystem path is its `path` field. */
export const parsePathInput = <T extends { readonly path: string }>(
  operation: string,
  schema: z.ZodType<T>,
  rawInput: unknown,
): Result<T, AnalysisInputError> =>
  parseInputWithAbsolutePaths(operation, schema, rawInput, (input) => [
    [["path"], input.path],
  ]);

/** Evidence for a validated inline report, recording the caller's set parameters. */
export const inlineReportEvidence = (
  operation: string,
  execution: AnalysisExecution,
  input: object,
  result: JsonValue,
  confidence: NonNullable<EvidenceObservation["confidence"]>,
): Evidence =>
  createEvidence(execution.subject ?? undefined, execution.provider, {
    operation,
    parameters: Object.fromEntries(
      Object.entries(input).filter(([, value]) => value !== undefined),
    ) as Readonly<Record<string, JsonValue>>,
    result,
    ...(execution.rawResult === null ? {} : { rawResult: execution.rawResult }),
    confidence,
    locations: execution.locations,
    limitations: execution.limitations,
  });

/** The parse step and per-tool contract one inline report inspection needs. */
export interface ReportInspectionContract<Input, Report> {
  readonly operation: string;
  readonly parseInput: (rawInput: unknown) => Result<Input, AnalysisInputError>;
  readonly reportSchema: z.ZodType<Report>;
  /** The report must describe the selection the caller requested. */
  readonly matchesSelection: (report: Report, input: Input) => boolean;
  /** The caller input field naming the analyzed artifact. */
  readonly inputPath: (input: Input) => string;
  /** The report's own record of the same artifact path; when the tool
   * echoes no artifact path this must compare against the same value. */
  readonly reportPath: (report: Report) => string | undefined;
  /** The report field carrying the analyzed artifact's digest. */
  readonly reportSha256: (report: Report) => string | undefined;
  readonly malformedMessage: string;
  readonly confidence: NonNullable<EvidenceObservation["confidence"]>;
}

/**
 * Load, validate and evidence one tool report: the shared body of the
 * CLI/MCP report services whose providers run through a binary session.
 */
export const inspectInlineReport = async <
  Input extends object,
  Report extends JsonValue,
>(
  contract: ReportInspectionContract<Input, Report>,
  load: (
    input: Input,
    options?: ExecutionOptions,
  ) => Promise<Result<AnalysisExecution, AnalysisError>>,
  rawInput: unknown,
  options?: ExecutionOptions,
): Promise<Result<Evidence, AnalysisError>> => {
  if (options?.signal?.aborted)
    return err(new AnalysisCancelledError(contract.operation));
  const input = contract.parseInput(rawInput);
  if (!input.ok) return input;
  const inspected = await load(input.value, options);
  if (!inspected.ok) return inspected;
  if (options?.signal?.aborted)
    return err(new AnalysisCancelledError(contract.operation));
  const execution = inspected.value;
  const report = contract.reportSchema.safeParse(execution.result);
  if (
    !report.success ||
    contract.reportPath(report.data) !== contract.inputPath(input.value) ||
    !contract.matchesSelection(report.data, input.value) ||
    execution.subject?.path !== contract.inputPath(input.value) ||
    execution.subject.sha256 !== contract.reportSha256(report.data)
  )
    return err(
      new AnalysisOutputError(contract.operation, contract.malformedMessage),
    );
  return ok(
    inlineReportEvidence(
      contract.operation,
      execution,
      input.value,
      report.data,
      contract.confidence,
    ),
  );
};
