import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parsePathInput } from "../InlineReportService.js";
import type { BytePatternPort } from "./BytePatternPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  bytePatternScanSchema,
  scanBytePatternsInputSchema,
  type BytePatternScan,
  type ScanBytePatternsInput,
} from "../../domain/patterns/bytePatterns.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "scan_byte_patterns";

/** One result per requested pattern, in order, within the match limit. */
const matchesSelection = (
  report: BytePatternScan,
  input: ScanBytePatternsInput,
): boolean =>
  report.file.path === input.path &&
  report.results.length === input.patterns.length &&
  report.results.every(
    (result, index) =>
      result.name === (input.patterns[index]?.name ?? null) &&
      result.matches.length <= input.max_matches &&
      result.matches.length <= result.total_matches,
  );

/** Shared AOB-scan validation and typed inline Evidence for CLI/MCP. */
export class BytePatternService {
  constructor(readonly provider: BytePatternPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async scan(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      scanBytePatternsInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    const scanned = await this.provider.scan(input.value, options);
    if (!scanned.ok) return scanned;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = scanned.value;
    const report = bytePatternScanSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Byte-pattern scanner returned malformed data, changed the selected file identity or a different set of patterns.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: input.value as unknown as Readonly<
          Record<string, JsonValue>
        >,
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
