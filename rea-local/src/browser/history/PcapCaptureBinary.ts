import { CaptureFormatError } from "./CaptureFormatError.js";
import type { Endian } from "./PcapCaptureTypes.js";

export const macAddress = (bytes: Buffer, offset: number): string =>
  bytes
    .subarray(offset, offset + 6)
    .toString("hex")
    .match(/.{2}/g)
    ?.join(":") ?? "";

export const ipv4Address = (bytes: Buffer, offset: number): string =>
  `${bytes[offset] ?? 0}.${bytes[offset + 1] ?? 0}.${bytes[offset + 2] ?? 0}.${bytes[offset + 3] ?? 0}`;

export const ipv6Address = (bytes: Buffer, offset: number): string => {
  const words = Array.from({ length: 8 }, (_, index) =>
    bytes.readUInt16BE(offset + index * 2),
  );
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index++;
      continue;
    }
    let end = index;
    while (end < words.length && words[end] === 0) end++;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const formatted = words.map((word) => word.toString(16));
  if (bestStart < 0) return formatted.join(":");
  const left = formatted.slice(0, bestStart).join(":");
  const right = formatted.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
};

export const alignToFour = (value: number): number => (value + 3) & ~3;

export const requireRange = (
  bytes: Buffer,
  offset: number,
  length: number,
  label: string,
): void => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > bytes.length ||
    length > bytes.length - offset
  )
    throw new CaptureFormatError(
      "format",
      `${label} is truncated or outside the retained capture at byte offset ${offset}.`,
    );
};

export const readU16 = (
  bytes: Buffer,
  offset: number,
  endian: Endian,
  label: string,
): number => {
  requireRange(bytes, offset, 2, label);
  return endian === "little"
    ? bytes.readUInt16LE(offset)
    : bytes.readUInt16BE(offset);
};

export const readU32 = (
  bytes: Buffer,
  offset: number,
  endian: Endian,
  label: string,
): number => {
  requireRange(bytes, offset, 4, label);
  return endian === "little"
    ? bytes.readUInt32LE(offset)
    : bytes.readUInt32BE(offset);
};

export const readI32 = (
  bytes: Buffer,
  offset: number,
  endian: Endian,
  label: string,
): number => {
  requireRange(bytes, offset, 4, label);
  return endian === "little"
    ? bytes.readInt32LE(offset)
    : bytes.readInt32BE(offset);
};

export const readI64 = (
  bytes: Buffer,
  offset: number,
  endian: Endian,
  label: string,
): bigint => {
  requireRange(bytes, offset, 8, label);
  return endian === "little"
    ? bytes.readBigInt64LE(offset)
    : bytes.readBigInt64BE(offset);
};

export const validatePacketLengths = (
  captured: number,
  original: number,
  snapLength: number,
  offset: number,
): void => {
  if (captured > original || (snapLength !== 0 && captured > snapLength))
    throw new CaptureFormatError(
      "format",
      `Captured/original packet lengths are inconsistent at byte offset ${offset}.`,
    );
};
