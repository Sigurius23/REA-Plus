import { createHash } from "node:crypto";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  WEB_NETWORK_CAPTURE_LIMITS,
  type WebNetworkCaptureRecord,
} from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { CaptureRedaction, capturePointer } from "./CaptureRedaction.js";
import { decodeFrame } from "./PcapFrameDecoder.js";
import { LIMITATIONS, MAX_OUTPUT_RESERVE } from "./PcapCaptureLimits.js";
import type {
  InterfaceDescription,
  PacketCollector,
  PacketDescription,
  Projection,
  TimestampDescription,
  UnknownObject,
} from "./PcapCaptureTypes.js";

export const addPacket = (
  collector: PacketCollector,
  packet: PacketDescription,
): void => {
  if (packet.ordinal !== collector.packetCount)
    throw new TypeError("Packet ordinal sequence changed while decoding.");
  collector.packetCount++;
  if (
    collector.requested !== undefined &&
    !collector.requested.has(packet.ordinal)
  )
    return;
  if (collector.outputLimitReached) return;
  const record = createPacketRecord(collector, packet);
  const serializedBytes = Buffer.byteLength(JSON.stringify(record), "utf8") + 1;
  if (
    collector.estimatedReplyBytes + serializedBytes >
    WEB_NETWORK_CAPTURE_LIMITS.outputBytes - MAX_OUTPUT_RESERVE
  ) {
    collector.outputLimitReached = true;
    collector.recordsByOrdinal.clear();
    return;
  }
  collector.estimatedReplyBytes += serializedBytes;
  collector.recordsByOrdinal.set(packet.ordinal, record);
};

const createPacketRecord = (
  collector: PacketCollector,
  packet: PacketDescription,
): WebNetworkCaptureRecord => {
  const frameBytes = collector.bytes.subarray(
    packet.dataOffset,
    packet.dataOffset + packet.capturedBytes,
  );
  const decoded = decodeFrame(frameBytes, packet.linkType);
  const redactor = new CaptureRedaction(collector.sensitiveValues);
  const projection = projectPcapValue(
    packetReported(packet, decoded),
    collector.sensitiveValues,
    redactor,
  );
  if (packet.timestamp?.exactTicks !== undefined)
    preserveWideTimestamp(
      packet.timestamp.exactTicks,
      collector.sensitiveValues,
      projection,
    );
  const binary_fields = packetBinaryFields(
    frameBytes,
    redactor,
    collector.sensitiveValues,
  );
  return {
    ordinal: packet.ordinal,
    location: {
      kind: "byte-range",
      offset: packet.recordOffset,
      bytes: packet.recordBytes,
    },
    reported: projection.reported,
    numeric_literals: projection.numeric_literals,
    binary_fields,
    redactions: redactor.redactions,
    limitations: [...LIMITATIONS],
  };
};

const packetReported = (
  packet: PacketDescription,
  decoded: ReturnType<typeof decodeFrame>,
): UnknownObject => ({
  frame: {
    record_kind: packet.recordKind,
    record_offset: packet.recordOffset,
    record_bytes: packet.recordBytes,
    packet_data_offset: packet.dataOffset,
    captured_bytes: packet.capturedBytes,
    original_bytes: packet.originalBytes,
    truncated: packet.capturedBytes < packet.originalBytes,
    link_type: packet.linkType,
    ...(packet.sectionIndex === undefined
      ? {}
      : { section_index: packet.sectionIndex }),
    ...(packet.interfaceIndex === undefined
      ? {}
      : { interface_index: packet.interfaceIndex }),
    ...(packet.fcsLength === undefined || packet.fcsLength === null
      ? {}
      : { fcs_length: packet.fcsLength }),
    ...(packet.timestamp === undefined
      ? {}
      : { timestamp: packet.timestamp.reported }),
    decode_status: decoded.status,
  },
  link: decoded.link,
  network: decoded.network,
  transport: decoded.transport,
  flow: decoded.flow,
});

const packetBinaryFields = (
  frameBytes: Buffer,
  redactor: CaptureRedaction,
  sensitiveValues: readonly string[],
): WebNetworkCaptureRecord["binary_fields"] => {
  const base64 = frameBytes.toString("base64");
  const sha256 = createHash("sha256").update(frameBytes).digest("hex");
  const hidden =
    redactor.sensitiveBytes(frameBytes) ||
    sensitiveValues.some(
      (literal) => base64.includes(literal) || sha256.includes(literal),
    );
  if (hidden)
    redactor.redactions.push({
      pointer: "/frame/data",
      reason: "explicit-sensitive-value",
    });
  return [
    hidden
      ? {
          pointer: "/frame/data",
          representation: "producer-bytes",
          state: "redacted",
          content_base64: null,
          bytes: null,
          sha256: null,
        }
      : {
          pointer: "/frame/data",
          representation: "producer-bytes",
          state: "retained",
          content_base64: base64,
          bytes: frameBytes.length,
          sha256,
        },
  ];
};

const preserveWideTimestamp = (
  ticks: bigint,
  sensitiveValues: readonly string[],
  projection: Projection,
): void => {
  if (ticks <= BigInt(Number.MAX_SAFE_INTEGER)) return;
  const literal = ticks.toString();
  const pointer = "/frame/timestamp/ticks";
  if (sensitiveValues.some((secret) => literal.includes(secret))) {
    projection.redactions.push({
      pointer,
      reason: "explicit-sensitive-value",
    });
    return;
  }
  projection.numeric_literals.push({
    pointer,
    producer_type: "integer",
    literal,
  });
};

export const projectPcapValue = (
  value: unknown,
  sensitiveValues: readonly string[],
  redactor: CaptureRedaction,
): Projection => {
  const numeric_literals: Projection["numeric_literals"] = [];
  const visit = (item: unknown, pointer: string): JsonValue => {
    if (typeof item === "string") return redactor.text(item, pointer);
    if (typeof item === "number") {
      const literal = String(item);
      if (sensitiveValues.some((secret) => literal.includes(secret))) {
        redactor.redactions.push({
          pointer,
          reason: "explicit-sensitive-value",
        });
        return null;
      }
      numeric_literals.push({
        pointer,
        producer_type: "integer",
        literal,
      });
      return item;
    }
    if (item === null || typeof item === "boolean") return item;
    if (Array.isArray(item))
      return item.map((child, index) =>
        visit(child, capturePointer(pointer, String(index))),
      );
    if (typeof item === "object")
      return Object.fromEntries(
        Object.entries(item).flatMap(([key, child]) => {
          if (sensitiveValues.some((secret) => key.includes(secret))) {
            const beforeNumbers = numeric_literals.length;
            const beforeRedactions = redactor.redactions.length;
            visit(child, capturePointer(pointer, key));
            numeric_literals.splice(beforeNumbers);
            redactor.redactions.splice(beforeRedactions);
            redactor.redactions.push({
              pointer,
              reason: "explicit-sensitive-value",
              scope: "property-name",
            });
            return [];
          }
          return [[key, visit(child, capturePointer(pointer, key))]];
        }),
      );
    throw new CaptureFormatError(
      "format",
      "Packet decoder produced a non-JSON metadata value.",
      pointer,
    );
  };
  return {
    reported: visit(value, ""),
    numeric_literals,
    binary_fields: [],
    redactions: redactor.redactions,
  };
};

export const classicTimestamp = (
  seconds: number,
  fraction: number,
  exponent: number,
): TimestampDescription => {
  const scale = 10n ** BigInt(exponent);
  const ticks = BigInt(seconds) * scale + BigInt(fraction);
  return {
    reported: {
      seconds,
      fraction,
      precision: exponent === 9 ? "nanoseconds" : "microseconds",
      unix_seconds: decimalTimestamp(ticks, 10, exponent, 0n),
    },
  };
};

export const pcapNgTimestamp = (
  ticks: bigint,
  interfaceDescription: InterfaceDescription,
): TimestampDescription => ({
  reported: {
    ticks: ticks <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(ticks) : null,
    ticks_decimal: ticks.toString(),
    resolution_base: interfaceDescription.resolutionBase,
    resolution_exponent: interfaceDescription.resolutionExponent,
    offset_seconds: interfaceDescription.offsetSeconds.toString(),
    unix_seconds: decimalTimestamp(
      ticks,
      interfaceDescription.resolutionBase,
      interfaceDescription.resolutionExponent,
      interfaceDescription.offsetSeconds,
    ),
  },
  exactTicks: ticks,
});

const decimalTimestamp = (
  ticks: bigint,
  base: 2 | 10,
  exponent: number,
  offsetSeconds: bigint,
): string => {
  const scale = 10n ** BigInt(exponent);
  const scaledTicks = base === 10 ? ticks : ticks * 5n ** BigInt(exponent);
  const value = scaledTicks + offsetSeconds * scale;
  const negative = value < 0n;
  const absolute = negative ? -value : value;
  const whole = absolute / scale;
  const remainder = absolute % scale;
  const fraction =
    remainder === 0n
      ? ""
      : remainder.toString().padStart(exponent, "0").replace(/0+$/, "");
  return `${negative ? "-" : ""}${whole.toString()}${fraction === "" ? "" : `.${fraction}`}`;
};
