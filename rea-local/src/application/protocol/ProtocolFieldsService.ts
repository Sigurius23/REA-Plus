import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { ProtocolFieldsPort } from "./ProtocolFieldsPort.js";
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
  inferProtocolFieldsInputSchema,
  protocolFieldsSchema,
  PROTOCOL_VIEWS,
  type InferProtocolFieldsInput,
  type ProtocolFieldsReport,
} from "../../domain/protocol/protocolFields.js";

const OPERATION = "infer_protocol_fields";

/** The report must describe the selected file, view, format and page. */
const matchesSelection = (
  report: ProtocolFieldsReport,
  input: InferProtocolFieldsInput,
): boolean => {
  const { page } = report;
  const rows = PROTOCOL_VIEWS.reduce(
    (sum, view) => sum + report[view].length,
    0,
  );
  const formatHolds =
    input.format === undefined ||
    input.view === "flows" ||
    (input.view === "formats"
      ? report.formats.every(({ id }) => id === input.format)
      : report[input.view].every(({ format }) => format === input.format));
  return (
    report.file.path === input.path &&
    page.view === input.view &&
    page.format === (input.format ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    formatHolds
  );
};

/** Shared protocol inference validation and typed inline Evidence for CLI/MCP. */
export class ProtocolFieldsService {
  constructor(readonly provider: ProtocolFieldsPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inferProtocolFieldsInputSchema.safeParse(rawInput);
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
    const report = protocolFieldsSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Protocol inference returned malformed data, changed the selected file, or returned a different view, format or page than requested.",
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
