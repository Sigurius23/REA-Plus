import { fileURLToPath } from "node:url";
import type { HistoricalCaptureFormatAdapter } from "./HistoricalCaptureFormatAdapter.js";
import {
  BURP_CAPTURE_PROVIDER_IDENTITY,
  HAR_CAPTURE_HEAP_LIMITS,
  HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES,
} from "./CaptureRelease.js";

/** Burp XML is converted and decoded in one bounded Node heap, without network or target execution. */
export class BurpCaptureAdapter implements HistoricalCaptureFormatAdapter {
  readonly format = "burp";
  readonly identity = BURP_CAPTURE_PROVIDER_IDENTITY;
  async command(requestPath: string): Promise<{
    command: string;
    arguments: readonly string[];
    memoryLimitBytes?: number;
  }> {
    return {
      command: process.execPath,
      arguments: [
        `--max-old-space-size=${HAR_CAPTURE_HEAP_LIMITS.oldGenerationMiB}`,
        `--max-semi-space-size=${HAR_CAPTURE_HEAP_LIMITS.semiSpaceMiB}`,
        "--v8-pool-size=1",
        "--single-threaded",
        fileURLToPath(new URL("./BurpCaptureProcess.js", import.meta.url)),
        requestPath,
      ],
      ...(HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES === null
        ? {}
        : { memoryLimitBytes: HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES }),
    };
  }
}
