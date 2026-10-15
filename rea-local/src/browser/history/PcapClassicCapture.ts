import { CaptureFormatError } from "./CaptureFormatError.js";
import {
  readI32,
  readU16,
  readU32,
  requireRange,
  validatePacketLengths,
} from "./PcapCaptureBinary.js";
import { PCAPNG_SECTION_HEADER_MAGIC } from "./PcapCaptureLimits.js";
import { addPacket, classicTimestamp } from "./PcapCaptureProjection.js";
import type {
  Endian,
  PacketCollector,
  UnknownObject,
} from "./PcapCaptureTypes.js";

export const decodeClassicPcap = (
  collector: PacketCollector,
): UnknownObject => {
  const { bytes } = collector;
  const header = parseClassicHeader(bytes);
  let cursor = 24;
  while (cursor < bytes.length) {
    if (bytes.length - cursor < 16)
      throw new CaptureFormatError(
        "format",
        `Classic PCAP packet header is truncated at byte offset ${cursor}.`,
      );
    const seconds = readU32(
      bytes,
      cursor,
      header.endian,
      "PCAP packet timestamp seconds",
    );
    const fraction = readU32(
      bytes,
      cursor + 4,
      header.endian,
      "PCAP packet timestamp fraction",
    );
    const capturedBytes = readU32(
      bytes,
      cursor + 8,
      header.endian,
      "PCAP captured length",
    );
    const originalBytes = readU32(
      bytes,
      cursor + 12,
      header.endian,
      "PCAP original length",
    );
    if (fraction >= 10 ** header.timestampExponent)
      throw new CaptureFormatError(
        "format",
        `Classic PCAP timestamp fraction is out of range at byte offset ${cursor}.`,
      );
    validatePacketLengths(
      capturedBytes,
      originalBytes,
      header.snapLength,
      cursor,
    );
    const dataOffset = cursor + 16;
    requireRange(bytes, dataOffset, capturedBytes, "PCAP packet data");
    const recordBytes = 16 + capturedBytes;
    addPacket(collector, {
      ordinal: collector.packetCount,
      recordKind: "classic-packet-record",
      recordOffset: cursor,
      recordBytes,
      dataOffset,
      capturedBytes,
      originalBytes,
      linkType: header.linkType,
      timestamp: classicTimestamp(seconds, fraction, header.timestampExponent),
    });
    cursor += recordBytes;
  }
  return {
    format: "pcap",
    byte_order: header.endian === "little" ? "little-endian" : "big-endian",
    version: `${header.major}.${header.minor}`,
    timestamp_precision: header.timestampPrecision,
    timezone_offset_seconds: header.timezoneOffset,
    timestamp_accuracy: header.timestampAccuracy,
    snapshot_length: header.snapLength,
    link_type: header.linkType,
    link_type_raw: header.rawLinkType,
  };
};

interface ClassicProfile {
  readonly endian: Endian;
  readonly timestampExponent: number;
  readonly timestampPrecision: "microseconds" | "nanoseconds";
}

const classicMagic = (hex: string): ClassicProfile | undefined => {
  switch (hex) {
    case "d4c3b2a1":
      return {
        endian: "little",
        timestampExponent: 6,
        timestampPrecision: "microseconds",
      };
    case "a1b2c3d4":
      return {
        endian: "big",
        timestampExponent: 6,
        timestampPrecision: "microseconds",
      };
    case "4d3cb2a1":
      return {
        endian: "little",
        timestampExponent: 9,
        timestampPrecision: "nanoseconds",
      };
    case "a1b23c4d":
      return {
        endian: "big",
        timestampExponent: 9,
        timestampPrecision: "nanoseconds",
      };
    default:
      return undefined;
  }
};

interface ClassicHeader extends ClassicProfile {
  readonly major: number;
  readonly minor: number;
  readonly timezoneOffset: number;
  readonly timestampAccuracy: number;
  readonly snapLength: number;
  readonly rawLinkType: number;
  readonly linkType: number;
}

const parseClassicHeader = (bytes: Buffer): ClassicHeader => {
  if (bytes.length < 4)
    throw new CaptureFormatError("format", "PCAP magic header is truncated.");
  if (bytes.subarray(0, 4).equals(PCAPNG_SECTION_HEADER_MAGIC))
    throw new CaptureFormatError(
      "format",
      "Input is PCAPNG, but the requested format is classic PCAP.",
    );
  const profile = classicMagic(bytes.subarray(0, 4).toString("hex"));
  if (profile === undefined)
    throw new CaptureFormatError(
      "format",
      "Unrecognized classic PCAP magic number.",
    );
  if (bytes.length < 24)
    throw new CaptureFormatError(
      "format",
      "Classic PCAP global header is truncated.",
    );
  const major = readU16(bytes, 4, profile.endian, "PCAP major version");
  const minor = readU16(bytes, 6, profile.endian, "PCAP minor version");
  if (major !== 2 || minor !== 4)
    throw new CaptureFormatError(
      "unsupported",
      `Classic PCAP version ${major}.${minor} is not supported; expected 2.4.`,
    );
  const rawLinkType = readU32(bytes, 20, profile.endian, "PCAP link type");
  return {
    ...profile,
    major,
    minor,
    timezoneOffset: readI32(bytes, 8, profile.endian, "PCAP timezone offset"),
    timestampAccuracy: readU32(
      bytes,
      12,
      profile.endian,
      "PCAP timestamp accuracy",
    ),
    snapLength: readU32(bytes, 16, profile.endian, "PCAP snapshot length"),
    rawLinkType,
    linkType: rawLinkType & 0xffff,
  };
};
