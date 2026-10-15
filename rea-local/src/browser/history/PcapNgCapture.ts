import { CaptureFormatError } from "./CaptureFormatError.js";
import {
  alignToFour,
  readU16,
  readU32,
  validatePacketLengths,
} from "./PcapCaptureBinary.js";
import {
  MAX_PCAPNG_INTERFACES,
  PCAPNG_SECTION_HEADER_MAGIC,
} from "./PcapCaptureLimits.js";
import { addPacket, pcapNgTimestamp } from "./PcapCaptureProjection.js";
import {
  getPcapNgInterface,
  parseInterfaceOptions,
  parseOptions,
  pcapNgEndian,
  requireBlockContent,
  validateBlockBounds,
} from "./PcapNgStructures.js";
import type {
  Endian,
  InterfaceDescription,
  PacketCollector,
  PacketDescription,
  UnknownObject,
} from "./PcapCaptureTypes.js";

interface PcapNgState {
  readonly collector: PacketCollector;
  endian: Endian | undefined;
  sectionIndex: number;
  sectionCount: number;
  interfaceCount: number;
  unknownBlockCount: number;
  littleEndianSections: number;
  bigEndianSections: number;
  interfaces: InterfaceDescription[];
}

interface BlockHeader {
  readonly type: number;
  readonly length: number;
  readonly end: number;
}

/** Walk every PCAPNG block, decoding packets while retaining only selected frames. */
export const decodePcapNg = (collector: PacketCollector): UnknownObject => {
  const bytes = collector.bytes;
  if (bytes.length < 4)
    throw new CaptureFormatError(
      "format",
      "PCAPNG section header is truncated.",
    );
  if (!bytes.subarray(0, 4).equals(PCAPNG_SECTION_HEADER_MAGIC))
    throw new CaptureFormatError(
      "format",
      "Input is not PCAPNG; the requested format is PCAPNG.",
    );
  const state: PcapNgState = {
    collector,
    endian: undefined,
    sectionIndex: -1,
    sectionCount: 0,
    interfaceCount: 0,
    unknownBlockCount: 0,
    littleEndianSections: 0,
    bigEndianSections: 0,
    interfaces: [],
  };
  walkBlocks(state);
  return describeContainer(state);
};

const walkBlocks = (state: PcapNgState): void => {
  const bytes = state.collector.bytes;
  let cursor = 0;
  while (cursor < bytes.length) {
    requireBlockHeader(bytes, cursor);
    if (isSectionHeader(bytes, cursor)) {
      cursor += parseSectionHeader(state, cursor);
      continue;
    }
    const endian = state.endian;
    if (endian === undefined || state.sectionIndex < 0)
      throw new CaptureFormatError(
        "format",
        `PCAPNG block occurs before a section header at byte offset ${cursor}.`,
      );
    const block = readBlockHeader(bytes, cursor, endian);
    parseBlock(state, cursor, block, endian);
    cursor += block.length;
  }
};

const requireBlockHeader = (bytes: Buffer, cursor: number): void => {
  if (bytes.length - cursor < 8)
    throw new CaptureFormatError(
      "format",
      `PCAPNG block header is truncated at byte offset ${cursor}.`,
    );
};

const isSectionHeader = (bytes: Buffer, cursor: number): boolean =>
  bytes.subarray(cursor, cursor + 4).equals(PCAPNG_SECTION_HEADER_MAGIC);

const parseSectionHeader = (state: PcapNgState, cursor: number): number => {
  const bytes = state.collector.bytes;
  if (bytes.length - cursor < 12)
    throw new CaptureFormatError(
      "format",
      `PCAPNG byte-order marker is truncated at byte offset ${cursor}.`,
    );
  const endian = pcapNgEndian(bytes, cursor + 8);
  const length = readU32(
    bytes,
    cursor + 4,
    endian,
    "PCAPNG section block length",
  );
  validateBlockBounds({
    bytes,
    offset: cursor,
    length,
    minimum: 28,
    endian,
    label: "section header",
  });
  validateSectionVersion(bytes, cursor, endian);
  parseOptions({ bytes, start: cursor + 24, end: cursor + length - 4, endian });
  state.endian = endian;
  state.sectionIndex++;
  state.sectionCount++;
  if (endian === "little") state.littleEndianSections++;
  else state.bigEndianSections++;
  state.interfaces = [];
  return length;
};

const validateSectionVersion = (
  bytes: Buffer,
  cursor: number,
  endian: Endian,
): void => {
  const major = readU16(bytes, cursor + 12, endian, "PCAPNG major version");
  const minor = readU16(bytes, cursor + 14, endian, "PCAPNG minor version");
  if (major !== 1 || minor !== 0)
    throw new CaptureFormatError(
      "unsupported",
      `PCAPNG section version ${major}.${minor} is not supported; expected 1.0.`,
    );
};

const readBlockHeader = (
  bytes: Buffer,
  cursor: number,
  endian: Endian,
): BlockHeader => {
  const type = readU32(bytes, cursor, endian, "PCAPNG block type");
  const length = readU32(bytes, cursor + 4, endian, "PCAPNG block length");
  validateBlockBounds({
    bytes,
    offset: cursor,
    length,
    minimum: 12,
    endian,
    label: "block",
  });
  return { type, length, end: cursor + length - 4 };
};

const parseBlock = (
  state: PcapNgState,
  cursor: number,
  block: BlockHeader,
  endian: Endian,
): void => {
  if (block.type === 0x00000001) {
    parseInterfaceBlock(state, cursor, block, endian);
    return;
  }
  if (block.type === 0x00000006 || block.type === 0x00000002) {
    parsePacketBlock({
      state,
      cursor,
      block,
      endian,
      obsolete: block.type === 0x00000002,
    });
    return;
  }
  if (block.type === 0x00000003) {
    parseSimplePacketBlock(state, cursor, block, endian);
    return;
  }
  state.unknownBlockCount++;
};

const parseInterfaceBlock = (
  state: PcapNgState,
  cursor: number,
  block: BlockHeader,
  endian: Endian,
): void => {
  if (block.length < 20)
    throw new CaptureFormatError(
      "format",
      `PCAPNG interface description is truncated at byte offset ${cursor}.`,
    );
  if (state.interfaces.length >= MAX_PCAPNG_INTERFACES)
    throw new CaptureFormatError(
      "input-limit",
      `PCAPNG exceeds the ${MAX_PCAPNG_INTERFACES}-interface section budget.`,
      "",
      {
        kind: "interfaces-per-section",
        maximum: MAX_PCAPNG_INTERFACES,
      },
    );
  const linkType = readU16(
    state.collector.bytes,
    cursor + 8,
    endian,
    "PCAPNG link type",
  );
  const reserved = readU16(
    state.collector.bytes,
    cursor + 10,
    endian,
    "PCAPNG interface reserved field",
  );
  if (reserved !== 0)
    throw new CaptureFormatError(
      "format",
      `PCAPNG interface reserved field is nonzero at byte offset ${cursor + 10}.`,
    );
  const snapLength = readU32(
    state.collector.bytes,
    cursor + 12,
    endian,
    "PCAPNG interface snapshot length",
  );
  const options = parseInterfaceOptions({
    bytes: state.collector.bytes,
    start: cursor + 16,
    end: block.end,
    endian,
  });
  state.interfaces.push({
    linkType,
    snapLength,
    resolutionBase: options.resolutionBase,
    resolutionExponent: options.resolutionExponent,
    offsetSeconds: options.offsetSeconds,
    fcsLength: options.fcsLength,
  });
  state.interfaceCount++;
};

interface PacketBlockInput {
  readonly state: PcapNgState;
  readonly cursor: number;
  readonly block: BlockHeader;
  readonly endian: Endian;
  readonly obsolete: boolean;
}

const parsePacketBlock = ({
  state,
  cursor,
  block,
  endian,
  obsolete,
}: PacketBlockInput): void => {
  if (block.length < 32)
    throw new CaptureFormatError(
      "format",
      `PCAPNG packet block is truncated at byte offset ${cursor}.`,
    );
  const interfaceIndex = obsolete
    ? readU16(
        state.collector.bytes,
        cursor + 8,
        endian,
        "PCAPNG packet interface index",
      )
    : readU32(
        state.collector.bytes,
        cursor + 8,
        endian,
        "PCAPNG enhanced packet interface index",
      );
  if (obsolete)
    readU16(
      state.collector.bytes,
      cursor + 10,
      endian,
      "PCAPNG packet drop count",
    );
  const ticks = readTimestampTicks(state.collector.bytes, cursor + 12, endian);
  const capturedBytes = readU32(
    state.collector.bytes,
    cursor + 20,
    endian,
    "PCAPNG captured length",
  );
  const originalBytes = readU32(
    state.collector.bytes,
    cursor + 24,
    endian,
    "PCAPNG original length",
  );
  const interfaceDescription = getPcapNgInterface(
    state.interfaces,
    interfaceIndex,
    cursor,
  );
  validatePacketLengths(
    capturedBytes,
    originalBytes,
    interfaceDescription.snapLength,
    cursor,
  );
  const dataOffset = cursor + 28;
  const paddedLength = alignToFour(capturedBytes);
  requireBlockContent({
    blockEnd: block.end,
    offset: dataOffset,
    length: paddedLength,
    blockOffset: cursor,
    label: "packet data",
  });
  parseOptions({
    bytes: state.collector.bytes,
    start: dataOffset + paddedLength,
    end: block.end,
    endian,
  });
  addPacket(
    state.collector,
    packetDescription(state, {
      cursor,
      block,
      dataOffset,
      capturedBytes,
      originalBytes,
      interfaceIndex,
      interfaceDescription,
      ticks,
      recordKind: obsolete ? "packet-block" : "enhanced-packet-block",
    }),
  );
};

interface PacketDescriptionInput {
  readonly cursor: number;
  readonly block: BlockHeader;
  readonly dataOffset: number;
  readonly capturedBytes: number;
  readonly originalBytes: number;
  readonly interfaceIndex: number;
  readonly interfaceDescription: InterfaceDescription;
  readonly ticks?: bigint;
  readonly recordKind: string;
}

const packetDescription = (
  state: PcapNgState,
  input: PacketDescriptionInput,
): PacketDescription => ({
  ordinal: state.collector.packetCount,
  recordKind: input.recordKind,
  recordOffset: input.cursor,
  recordBytes: input.block.length,
  dataOffset: input.dataOffset,
  capturedBytes: input.capturedBytes,
  originalBytes: input.originalBytes,
  linkType: input.interfaceDescription.linkType,
  ...(input.ticks === undefined
    ? {}
    : {
        timestamp: pcapNgTimestamp(input.ticks, input.interfaceDescription),
      }),
  sectionIndex: state.sectionIndex,
  interfaceIndex: input.interfaceIndex,
  fcsLength: input.interfaceDescription.fcsLength,
});

const readTimestampTicks = (
  bytes: Buffer,
  offset: number,
  endian: Endian,
): bigint =>
  (BigInt(readU32(bytes, offset, endian, "PCAPNG timestamp high word")) <<
    32n) |
  BigInt(readU32(bytes, offset + 4, endian, "PCAPNG timestamp low word"));

const parseSimplePacketBlock = (
  state: PcapNgState,
  cursor: number,
  block: BlockHeader,
  endian: Endian,
): void => {
  if (block.length < 16)
    throw new CaptureFormatError(
      "format",
      `PCAPNG simple packet block is truncated at byte offset ${cursor}.`,
    );
  const interfaceDescription = getPcapNgInterface(state.interfaces, 0, cursor);
  const originalBytes = readU32(
    state.collector.bytes,
    cursor + 8,
    endian,
    "PCAPNG simple packet original length",
  );
  const capturedBytes =
    interfaceDescription.snapLength === 0
      ? originalBytes
      : Math.min(originalBytes, interfaceDescription.snapLength);
  validatePacketLengths(
    capturedBytes,
    originalBytes,
    interfaceDescription.snapLength,
    cursor,
  );
  const dataOffset = cursor + 12;
  const paddedLength = alignToFour(capturedBytes);
  requireBlockContent({
    blockEnd: block.end,
    offset: dataOffset,
    length: paddedLength,
    blockOffset: cursor,
    label: "simple packet data",
  });
  if (dataOffset + paddedLength !== block.end)
    throw new CaptureFormatError(
      "format",
      `PCAPNG simple packet block has an unexpected options/trailer region at byte offset ${cursor}.`,
    );
  addPacket(
    state.collector,
    packetDescription(state, {
      cursor,
      block,
      dataOffset,
      capturedBytes,
      originalBytes,
      interfaceIndex: 0,
      interfaceDescription,
      recordKind: "simple-packet-block",
    }),
  );
};

const describeContainer = (state: PcapNgState): UnknownObject => ({
  format: "pcapng",
  byte_order:
    state.littleEndianSections > 0 && state.bigEndianSections > 0
      ? "mixed-endian-sections"
      : state.littleEndianSections > 0
        ? "little-endian"
        : "big-endian",
  section_version: "1.0",
  sections: state.sectionCount,
  interfaces: state.interfaceCount,
  packets: state.collector.packetCount,
  ignored_non_packet_blocks: state.unknownBlockCount,
});
