import { fileURLToPath } from "node:url";
import type { HistoricalCaptureFormatAdapter } from "./HistoricalCaptureFormatAdapter.js";
import {
  PCAP_CAPTURE_HEAP_LIMITS,
  PCAP_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES,
  PCAP_CAPTURE_PROVIDER_IDENTITY,
} from "./CaptureRelease.js";

/** Bounded Node worker for offline classic PCAP and PCAPNG inspection. */
export class PcapCaptureAdapter implements HistoricalCaptureFormatAdapter {
  readonly identity = PCAP_CAPTURE_PROVIDER_IDENTITY;
  constructor(readonly format: "pcap" | "pcapng") {}

  async command(requestPath: string): Promise<{
    command: string;
    arguments: readonly string[];
    memoryLimitBytes?: number;
  }> {
    return {
      command: process.execPath,
      arguments: [
        `--max-old-space-size=${PCAP_CAPTURE_HEAP_LIMITS.oldGenerationMiB}`,
        `--max-semi-space-size=${PCAP_CAPTURE_HEAP_LIMITS.semiSpaceMiB}`,
        "--v8-pool-size=1",
        "--single-threaded",
        fileURLToPath(new URL("./PcapCaptureProcess.js", import.meta.url)),
        requestPath,
        this.format,
      ],
      ...(PCAP_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES === null
        ? {}
        : { memoryLimitBytes: PCAP_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES }),
    };
  }
}
