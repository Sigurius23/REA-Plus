import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput, inspectInlineReport } from "../InlineReportService.js";
import type { MinidumpPort } from "./MinidumpPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  inspectMinidumpInputSchema,
  minidumpSchema,
  type InspectMinidumpInput,
  type Minidump,
} from "../../domain/minidump/minidump.js";

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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parsePathInput(OPERATION, inspectMinidumpInputSchema, rawInput),
        reportSchema: minidumpSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.dump.path,
        reportSha256: (report) => report.dump.sha256,
        malformedMessage:
          "Minidump reader returned malformed data, changed the selected dump identity or reported a different thread than requested.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
