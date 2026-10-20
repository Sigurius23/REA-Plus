import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { MinidumpPort } from "./MinidumpPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  inspectMinidumpInputSchema,
  minidumpSchema,
  type InspectMinidumpInput,
  type Minidump,
} from "../../domain/minidump/minidump.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_minidump";

/** The report must describe the selected dump and the requested thread. */
const matchesSelection = (
  report: Minidump,
  input: InspectMinidumpInput,
): boolean => {
  const selected = report.selected_thread;
  return (
    report.dump.path === input.path &&
    (input.thread_id === undefined || selected?.id === input.thread_id) &&
    (selected?.stack_scan.length ?? 0) <= input.stack_scan_limit
  );
};

/** Shared minidump validation and typed inline Evidence for CLI/MCP. */
export class MinidumpService {
  constructor(readonly provider: MinidumpPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectMinidumpInputSchema.safeParse(rawInput);
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
    const report = minidumpSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.dump.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Minidump reader returned malformed data, changed the selected dump identity or reported a different thread than requested.",
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
