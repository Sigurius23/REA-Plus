import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { CheatTablePort } from "./CheatTablePort.js";
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
    const input = inspectCheatTableInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = (["path", "binary_path"] as const).filter((field) => {
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
    const report = cheatTableSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.table.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Cheat-table reader returned malformed data or changed a selected file identity.",
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
