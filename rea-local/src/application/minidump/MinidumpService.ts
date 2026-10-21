import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { MinidumpPort } from "./MinidumpPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
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
    const input = parsePathInput(
      OPERATION,
      inspectMinidumpInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = minidumpSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.dump.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Minidump reader returned malformed data, changed the selected dump identity or reported a different thread than requested.",
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
