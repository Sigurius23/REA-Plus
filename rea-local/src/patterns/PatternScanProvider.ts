import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { BytePatternPort } from "../application/patterns/BytePatternPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  bytePatternScanSchema,
  type BytePatternScan,
  type ScanBytePatternsInput,
} from "../domain/patterns/bytePatterns.js";
import { err, ok, type Result } from "../domain/result.js";
import { BytePatternError, parseBytePattern } from "./BytePattern.js";
import { ImageLayoutError, type ImageLayout } from "./ImageLayout.js";
import {
  layoutRecord,
  readImageLayout,
  scanPatterns,
} from "./PatternScanner.js";

const OPERATION = "scan_byte_patterns";
/** Largest file read into memory for scanning. */
export const MAX_SCAN_BYTES = 1024 * 1024 * 1024;

export const BYTE_PATTERN_PROVIDER_IDENTITY = {
  id: "byte-pattern-scanner",
  name: "REA+ byte-pattern scanner",
  version: "1",
} as const;

export const BYTE_PATTERN_LIMITATIONS = [
  "Matches are byte comparisons in the file as stored; packed, encrypted or relocated-at-load code differs at runtime, and a pattern can match data that only looks like code.",
  "Every overlapping match is reported, as Cheat Engine's AOB scan does; radare2's /x resumes after each hit and can report fewer.",
  "Displacement targets read each run of exactly four ?? bytes as a little-endian rel32 measured from the end of the run, which is right for call/jmp rel32 and RIP-relative operands without a trailing immediate and wrong otherwise.",
  "Addresses use the file's preferred (link-time) image base; add the runtime slide for a live process.",
];

/** Map headers, falling back to raw offsets when they are malformed. */
export const mapImage = (
  bytes: Buffer,
): { readonly layout: ImageLayout; readonly error: string | null } => {
  try {
    return { layout: readImageLayout(bytes), error: null };
  } catch (cause: unknown) {
    if (!(cause instanceof ImageLayoutError)) throw cause;
    return {
      layout: {
        format: "raw",
        architecture: null,
        imageBase: null,
        sections: [],
      },
      error: cause.message,
    };
  }
};

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  return new AnalysisInputError(OPERATION, { cause }, [
    { path: ["path"], reason: "invalid_value", message: reason },
  ]);
};

/** Scan caller-selected bytes for AOB signatures; nothing is executed. */
export class PatternScanProvider implements BytePatternPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async scan(
    input: ScanBytePatternsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    const invalid = input.patterns.flatMap(({ pattern }, index) => {
      try {
        parseBytePattern(pattern);
        return [];
      } catch (cause: unknown) {
        if (!(cause instanceof BytePatternError)) throw cause;
        return [
          {
            path: ["patterns", index, "pattern"],
            reason: "invalid_format" as const,
            message: cause.message,
          },
        ];
      }
    });
    if (invalid.length > 0)
      return err(new AnalysisInputError(OPERATION, undefined, invalid));
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_SCAN_BYTES,
        signal,
      );
      const { layout, error } = mapImage(selected.bytes);
      const report: BytePatternScan = bytePatternScanSchema.parse({
        file: {
          path: input.path,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
          ...layoutRecord(layout),
          layout_error: error,
        },
        ...scanPatterns(selected.bytes, layout, input.patterns, {
          scope: input.scope,
          maxMatches: input.max_matches,
        }),
        limitations: BYTE_PATTERN_LIMITATIONS,
      });
      return ok(
        createAnalysisExecution(report, BYTE_PATTERN_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: BYTE_PATTERN_LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
