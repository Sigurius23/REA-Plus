import type { ExecutionOptions } from "../AnalysisProvider.js";
import { inspectInlineReport, parsePathInput } from "../InlineReportService.js";
import type { BytePatternPort } from "./BytePatternPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  bytePatternScanSchema,
  scanBytePatternsInputSchema,
  type BytePatternScan,
  type ScanBytePatternsInput,
} from "../../domain/patterns/bytePatterns.js";

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
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parsePathInput(OPERATION, scanBytePatternsInputSchema, rawInput),
        reportSchema: bytePatternScanSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.file.path,
        reportSha256: (report) => report.file.sha256,
        malformedMessage:
          "Byte-pattern scanner returned malformed data, changed the selected file identity or a different set of patterns.",
        confidence: "observed",
      },
      (input, invocation) => this.provider.scan(input, invocation),
      rawInput,
      options,
    );
  }
}
