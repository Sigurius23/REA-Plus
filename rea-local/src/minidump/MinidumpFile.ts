/** A minidump whose header, directory or a stream violates the format. */
export class MinidumpFormatError extends Error {}

/** Stream types REA+ decodes, by MINIDUMP_STREAM_TYPE value. */
export const STREAM_NAMES: Readonly<Record<number, string>> = {
  3: "ThreadList",
  4: "ModuleList",
  5: "MemoryList",
  6: "Exception",
  7: "SystemInfo",
  8: "ThreadExList",
  9: "Memory64List",
  10: "CommentA",
  11: "CommentW",
  12: "HandleData",
  13: "FunctionTable",
  14: "UnloadedModuleList",
  15: "MiscInfo",
  16: "MemoryInfoList",
  17: "ThreadInfoList",
  18: "HandleOperationList",
  19: "Token",
  20: "JavaScriptData",
  21: "SystemMemoryInfo",
  22: "ProcessVmCounters",
  23: "IptTrace",
  24: "ThreadNames",
  0x43500001: "CrashpadInfo",
  0x47670001: "BreakpadInfo",
  0x47670002: "AssertionInfo",
  0x47670003: "LinuxCpuInfo",
  0x47670004: "LinuxProcStatus",
  0x47670005: "LinuxLsbRelease",
  0x47670006: "LinuxCmdLine",
  0x47670007: "LinuxEnviron",
  0x47670008: "LinuxAuxv",
  0x47670009: "LinuxMaps",
  0x4767000a: "LinuxDsoDebug",
};

export interface MinidumpStream {
  readonly type: number;
  readonly rva: number;
  readonly size: number;
}

/** Bounds-checked little-endian reads over the dump bytes. */
export class MinidumpFile {
  readonly version: number;
  readonly implementation: number;
  readonly timestamp: number;
  readonly flags: bigint;
  readonly streams: readonly MinidumpStream[];

  constructor(readonly bytes: Buffer) {
    if (bytes.length < 32 || bytes.toString("latin1", 0, 4) !== "MDMP")
      throw new MinidumpFormatError("Missing the MDMP signature.");
    const version = bytes.readUInt32LE(4);
    if ((version & 0xffff) !== 0xa793)
      throw new MinidumpFormatError(
        `Unsupported minidump version 0x${(version & 0xffff).toString(16)}.`,
      );
    this.version = version & 0xffff;
    this.implementation = version >>> 16;
    const count = bytes.readUInt32LE(8);
    const directory = bytes.readUInt32LE(12);
    this.timestamp = bytes.readUInt32LE(20);
    this.flags = bytes.readBigUInt64LE(24);
    this.range(directory, count * 12, "stream directory");
    this.streams = Array.from({ length: count }, (_, index) => {
      const at = directory + index * 12;
      return {
        type: bytes.readUInt32LE(at),
        size: bytes.readUInt32LE(at + 4),
        rva: bytes.readUInt32LE(at + 8),
      };
    }).filter(({ type }) => type !== 0);
  }

  /** Require [rva, rva + size) inside the file. */
  range(rva: number, size: number, what: string): void {
    if (rva + size > this.bytes.length || rva < 0 || size < 0)
      throw new MinidumpFormatError(
        `${what} at 0x${rva.toString(16)} (+${String(size)} bytes) lies outside the ${String(this.bytes.length)}-byte dump.`,
      );
  }

  slice(rva: number, size: number, what: string): Buffer {
    this.range(rva, size, what);
    return this.bytes.subarray(rva, rva + size);
  }

  u16(rva: number): number {
    this.range(rva, 2, "u16");
    return this.bytes.readUInt16LE(rva);
  }

  u32(rva: number): number {
    this.range(rva, 4, "u32");
    return this.bytes.readUInt32LE(rva);
  }

  u64(rva: number): bigint {
    this.range(rva, 8, "u64");
    return this.bytes.readBigUInt64LE(rva);
  }

  /** MINIDUMP_STRING: a byte length, then UTF-16LE code units. */
  string(rva: number): string {
    const length = this.u32(rva);
    if (length % 2 !== 0 || length > 0x10000)
      throw new MinidumpFormatError(
        `MINIDUMP_STRING at 0x${rva.toString(16)} has invalid length ${String(length)}.`,
      );
    return this.slice(rva + 4, length, "MINIDUMP_STRING").toString("utf16le");
  }

  /** Streams of one type; a dump may repeat a type, and the first wins. */
  stream(type: number): MinidumpStream | undefined {
    return this.streams.find((stream) => stream.type === type);
  }
}
