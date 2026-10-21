import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { CheatTablePort } from "./CheatTablePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  inspectCheatTableInputSchema,
  cheatTableSchema,
  type InspectCheatTableInput,
  type CheatTableReport,
} from "../../domain/patterns/cheatTable.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_cheat_table";

/** The report must describe the selected table and, when given, binary. */
const matchesSelection = (
  report: CheatTableReport,
  input: InspectCheatTableInput,
): boolean =>
  report.table.path === input.path &&
  (report.binary_check?.file.path ?? null) === (input.binary_path ?? null);

/** Shared cheat-table validation and typed inline Evidence for CLI/MCP. */
export class CheatTableService {
  constructor(readonly provider: CheatTablePort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parseInputWithAbsolutePaths(
      OPERATION,
      inspectCheatTableInputSchema,
      rawInput,
      (input) => [
        [["path"], input.path],
        [["binary_path"], input.binary_path],
      ],
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = cheatTableSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.table.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Cheat-table reader returned malformed data or changed a selected file identity.",
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
