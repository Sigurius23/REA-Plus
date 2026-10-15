import { CaptureFormatError } from "./CaptureFormatError.js";
import {
  alignToFour,
  readI64,
  readU16,
  readU32,
  requireRange,
} from "./PcapCaptureBinary.js";
import type { Endian, InterfaceDescription } from "./PcapCaptureTypes.js";

interface BlockBoundsInput {
  readonly bytes: Buffer;
  readonly offset: number;
  readonly length: number;
  readonly minimum: number;
  readonly endian: Endian;
  readonly label: string;
}

interface BlockContentInput {
  readonly blockEnd: number;
  readonly offset: number;
  readonly length: number;
  readonly blockOffset: number;
  readonly label: string;
}

interface OptionsInput {
  readonly bytes: Buffer;
  readonly start: number;
  readonly end: number;
  readonly endian: Endian;
  readonly onOption?: OptionVisitor;
}

type OptionVisitor = (
  code: number,
  valueOffset: number,
  length: number,
) => void;

interface InterfaceOptions {
  readonly resolutionBase: 2 | 10;
  readonly resolutionExponent: number;
  readonly offsetSeconds: bigint;
  readonly fcsLength: number | null;
}

interface InterfaceOptionsInput {
  readonly bytes: Buffer;
  readonly start: number;
  readonly end: number;
  readonly endian: Endian;
}

export const parseInterfaceOptions = ({
  bytes,
  start,
  end,
  endian,
}: InterfaceOptionsInput): InterfaceOptions => {
  let resolutionBase: 2 | 10 = 10;
  let resolutionExponent = 6;
  let offsetSeconds = 0n;
  let fcsLength: number | null = null;
  let seenResolution = false;
  let seenOffset = false;
  let seenFcsLength = false;
  parseOptions({
    bytes,
    start,
    end,
    endian,
    onOption: (code, valueOffset, length) => {
      if (code === 9) {
        if (seenResolution || length !== 1)
          throw new CaptureFormatError(
            "format",
            "PCAPNG interface timestamp-resolution option is duplicated or malformed.",
          );
        seenResolution = true;
        const value = bytes[valueOffset] ?? 0;
        resolutionBase = (value & 0x80) === 0 ? 10 : 2;
        resolutionExponent = value & 0x7f;
      } else if (code === 14) {
        if (seenOffset || length !== 8)
          throw new CaptureFormatError(
            "format",
            "PCAPNG interface timestamp-offset option is duplicated or malformed.",
          );
        seenOffset = true;
        offsetSeconds = readI64(
          bytes,
          valueOffset,
          endian,
          "PCAPNG timestamp offset",
        );
      } else if (code === 13) {
        if (seenFcsLength || length !== 1)
          throw new CaptureFormatError(
            "format",
            "PCAPNG interface FCS-length option is duplicated or malformed.",
          );
        seenFcsLength = true;
        fcsLength = bytes[valueOffset] ?? 0;
      }
    },
  });
  return { resolutionBase, resolutionExponent, offsetSeconds, fcsLength };
};

export const parseOptions = ({
  bytes,
  start,
  end,
  endian,
  onOption,
}: OptionsInput): void => {
  if (start > end || start < 0 || end > bytes.length)
    throw new CaptureFormatError(
      "format",
      "PCAPNG option range is outside its block.",
    );
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < 4)
      throw new CaptureFormatError(
        "format",
        `PCAPNG option header is truncated at byte offset ${cursor}.`,
      );
    const code = readU16(bytes, cursor, endian, "PCAPNG option code");
    const length = readU16(bytes, cursor + 2, endian, "PCAPNG option length");
    cursor += 4;
    if (code === 0) {
      if (length !== 0 || cursor !== end)
        throw new CaptureFormatError(
          "format",
          `PCAPNG end-of-options marker is malformed at byte offset ${cursor - 4}.`,
        );
      return;
    }
    const paddedLength = alignToFour(length);
    requireRange(bytes, cursor, paddedLength, "PCAPNG option value");
    if (cursor + paddedLength > end)
      throw new CaptureFormatError(
        "format",
        `PCAPNG option exceeds its containing block at byte offset ${cursor - 4}.`,
      );
    onOption?.(code, cursor, length);
    cursor += paddedLength;
  }
};

export const getPcapNgInterface = (
  interfaces: readonly InterfaceDescription[],
  index: number,
  blockOffset: number,
): InterfaceDescription => {
  const item = interfaces[index];
  if (item === undefined)
    throw new CaptureFormatError(
      "format",
      `PCAPNG packet references missing interface ${index} at byte offset ${blockOffset}.`,
    );
  return item;
};

export const pcapNgEndian = (bytes: Buffer, offset: number): Endian => {
  requireRange(bytes, offset, 4, "PCAPNG byte-order marker");
  const marker = bytes.subarray(offset, offset + 4).toString("hex");
  if (marker === "4d3c2b1a") return "little";
  if (marker === "1a2b3c4d") return "big";
  throw new CaptureFormatError(
    "format",
    `Invalid PCAPNG byte-order marker at byte offset ${offset}.`,
  );
};

export const validateBlockBounds = ({
  bytes,
  offset,
  length,
  minimum,
  endian,
  label,
}: BlockBoundsInput): void => {
  if (length < minimum || length % 4 !== 0 || length > bytes.length - offset)
    throw new CaptureFormatError(
      "format",
      `PCAPNG ${label} length is invalid at byte offset ${offset}.`,
    );
  const trailingLength = readU32(
    bytes,
    offset + length - 4,
    endian,
    "PCAPNG trailing block length",
  );
  if (trailingLength !== length)
    throw new CaptureFormatError(
      "format",
      `PCAPNG block lengths disagree at byte offset ${offset}.`,
    );
};

export const requireBlockContent = ({
  blockEnd,
  offset,
  length,
  blockOffset,
  label,
}: BlockContentInput): void => {
  if (
    offset < 0 ||
    length < 0 ||
    offset > blockEnd ||
    length > blockEnd - offset
  )
    throw new CaptureFormatError(
      "format",
      `PCAPNG ${label} exceeds its block at byte offset ${blockOffset}.`,
    );
};
