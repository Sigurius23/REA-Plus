import {
  WEB_NETWORK_CAPTURE_LIMITS,
  type WebNetworkCapture,
  type WebNetworkCaptureRecord,
} from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { CaptureRedaction } from "./CaptureRedaction.js";
import { PCAP_CAPTURE_PROVIDER_IDENTITY } from "./CaptureRelease.js";
import { decodeClassicPcap } from "./PcapClassicCapture.js";
import { decodePcapNg } from "./PcapNgCapture.js";
import { projectPcapValue } from "./PcapCaptureProjection.js";
import type { PacketCollector, PcapFormat } from "./PcapCaptureTypes.js";

type DecodedCapture = Omit<
  WebNetworkCapture,
  "artifact" | "format" | "runtime_attribution" | "limitations"
>;

/** Parse classic PCAP or PCAPNG entirely offline, retaining only requested packet records. */
export const decodePcapCapture = (
  source: Uint8Array,
  format: PcapFormat,
  sensitiveValues: readonly string[],
  recordOrdinals?: readonly number[],
): DecodedCapture => {
  if (source.byteLength > WEB_NETWORK_CAPTURE_LIMITS.inputBytes)
    throw new CaptureFormatError(
      "input-limit",
      `Packet capture exceeds the ${WEB_NETWORK_CAPTURE_LIMITS.inputBytes}-byte input budget.`,
      "",
      {
        kind: "capture-bytes",
        maximum: WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
      },
    );
  const bytes = Buffer.from(
    source.buffer,
    source.byteOffset,
    source.byteLength,
  );
  const requested =
    recordOrdinals === undefined ? undefined : new Set(recordOrdinals);
  const collector: PacketCollector = {
    bytes,
    ...(requested === undefined ? {} : { requested }),
    sensitiveValues,
    recordsByOrdinal: new Map(),
    packetCount: 0,
    estimatedReplyBytes: 0,
    outputLimitReached: false,
  };

  const container =
    format === "pcap" ? decodeClassicPcap(collector) : decodePcapNg(collector);
  if (collector.outputLimitReached)
    throw new CaptureFormatError(
      "limit",
      "Selected packet records exceed the complete-evidence output budget.",
    );
  const records: WebNetworkCaptureRecord[] = [];
  if (recordOrdinals === undefined) {
    for (let ordinal = 0; ordinal < collector.packetCount; ordinal++) {
      const record = collector.recordsByOrdinal.get(ordinal);
      if (record === undefined)
        throw new TypeError("Packet decoder omitted a requested frame.");
      records.push(record);
    }
  } else {
    for (const ordinal of recordOrdinals) {
      if (ordinal >= collector.packetCount) continue;
      const record = collector.recordsByOrdinal.get(ordinal);
      if (record === undefined)
        throw new TypeError("Packet decoder omitted a requested frame.");
      records.push(record);
    }
  }

  const containerProjection = projectPcapValue(
    container,
    sensitiveValues,
    new CaptureRedaction(sensitiveValues),
  );
  return {
    decoder: { ...PCAP_CAPTURE_PROVIDER_IDENTITY },
    container: {
      reported: containerProjection.reported,
      numeric_literals: containerProjection.numeric_literals,
      redactions: containerProjection.redactions,
      records_pointer: null,
    },
    total_records: collector.packetCount,
    records,
  };
};
