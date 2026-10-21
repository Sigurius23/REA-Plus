import { isAbsolute } from "node:path";
import type { z } from "zod";

import type { AnalysisExecution } from "./AnalysisProvider.js";
import {
  AnalysisInputError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceObservation,
} from "../domain/evidence.js";
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
