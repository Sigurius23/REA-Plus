import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput } from "../InlineReportService.js";
import type { RecordedCrashPort } from "./RecordedCrashPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectRecordedCrashInputSchema,
  recordedCrashSchema,
} from "../../domain/native/recordedCrash.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_recorded_crash";

/** Shared CLI/MCP validation and Evidence composition for recorded crash inspection. */
export class RecordedCrashService {
  constructor(readonly provider: RecordedCrashPort) {}

  /** Bind complete observations to the caller-selected artifact before creating Evidence. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectRecordedCrashInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    const diagnostics = recordedCrashSchema.shape.diagnostics.safeParse(
      inspected.value.diagnostics,
    );
    const outputOptions = diagnostics.success
      ? { capturedOutput: diagnostics.data }
      : undefined;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION, outputOptions));
    const report = recordedCrashSchema.safeParse(inspected.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.value.path ||
      (report.data.debugger.status === "available") !==
        input.value.include_debugger_context
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Recorded crash provider returned malformed evidence or changed the selected artifact identity.",
          outputOptions,
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          format: "elf",
          architecture: "x86_64",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.value,
          result: value,
          // The decoded report is the only representation; do not repeat it.
          rawResult: null,
          confidence:
            value.debugger.status === "available" ? "derived" : "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}
