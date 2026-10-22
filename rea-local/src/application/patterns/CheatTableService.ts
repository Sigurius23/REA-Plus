import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { CheatTablePort } from "./CheatTablePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  inspectCheatTableInputSchema,
  cheatTableSchema,
  type InspectCheatTableInput,
  type CheatTableReport,
} from "../../domain/patterns/cheatTable.js";

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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parseInputWithAbsolutePaths(
            OPERATION,
            inspectCheatTableInputSchema,
            rawInput,
            (input) => [
              [["path"], input.path],
              [["binary_path"], input.binary_path],
            ],
          ),
        reportSchema: cheatTableSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.table.path,
        reportSha256: (report) => report.table.sha256,
        malformedMessage:
          "Cheat-table reader returned malformed data or changed a selected file identity.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
