import { MinidumpFormatError, type MinidumpFile } from "./MinidumpFile.js";

export interface LocationDescriptor {
  readonly size: number;
  readonly rva: number;
}

export interface RawThread {
  readonly id: number;
  readonly suspendCount: number;
  readonly priorityClass: number;
  readonly priority: number;
  readonly teb: bigint;
  readonly stackStart: bigint;
  readonly stack: LocationDescriptor;
  readonly context: LocationDescriptor;
}

export interface RawModule {
  readonly base: bigint;
  readonly size: number;
  readonly checksum: number;
  readonly timestamp: number;
  readonly name: string;
  readonly fileVersion: string | null;
  readonly productVersion: string | null;
  readonly codeView: CodeView | null;
}

export type CodeView =
  | {
      readonly format: "RSDS";
      readonly pdb: string;
      readonly guid: string;
      readonly age: number;
      readonly debugId: string;
    }
  | {
      readonly format: "NB10";
      readonly pdb: string;
      readonly signature: number;
      readonly age: number;
      readonly debugId: string;
    }
  | {
      readonly format: "ELF build ID";
      readonly buildId: string;
      readonly debugId: string;
    }
  | { readonly format: "unknown"; readonly signature: string };

export interface MemoryRange {
  readonly start: bigint;
  readonly size: bigint;
  /** File offset of the captured bytes. */
  readonly rva: number;
}

export interface RawException {
  readonly threadId: number;
  readonly code: number;
  readonly flags: number;
  readonly address: bigint;
  readonly parameters: readonly bigint[];
  readonly context: LocationDescriptor;
}

export interface RawSystemInfo {
  readonly architecture: number;
  readonly processorLevel: number;
  readonly processorRevision: number;
  readonly processors: number;
  readonly productType: number;
  readonly major: number;
  readonly minor: number;
  readonly build: number;
  readonly platform: number;
  readonly csdVersion: string | null;
  readonly cpuVendor: string | null;
}

const location = (file: MinidumpFile, at: number): LocationDescriptor => ({
  size: file.u32(at),
  rva: file.u32(at + 4),
});

/** Count-prefixed fixed-size records; the stream must hold them all. */
const records = (
  file: MinidumpFile,
  type: number,
  entry: number,
  header = 4,
): { readonly at: number; readonly count: number } | null => {
  const stream = file.stream(type);
  if (stream === undefined) return null;
  const count = file.u32(stream.rva);
  if (header + count * entry > stream.size)
    throw new MinidumpFormatError(
      `Stream ${String(type)} declares ${String(count)} entries but holds ${String(stream.size)} bytes.`,
    );
  file.range(stream.rva, stream.size, `stream ${String(type)}`);
  return { at: stream.rva + header, count };
};

export const readThreads = (file: MinidumpFile): RawThread[] | null => {
  const table = records(file, 3, 48);
  if (table === null) return null;
  return Array.from({ length: table.count }, (_, index) => {
    const at = table.at + index * 48;
    return {
      id: file.u32(at),
      suspendCount: file.u32(at + 4),
      priorityClass: file.u32(at + 8),
      priority: file.u32(at + 12),
      teb: file.u64(at + 16),
      stackStart: file.u64(at + 24),
      stack: location(file, at + 32),
      context: location(file, at + 40),
    };
  });
};

const version = (high: number, low: number): string =>
  [high >>> 16, high & 0xffff, low >>> 16, low & 0xffff].join(".");

const hexBytes = (bytes: Buffer): string => bytes.toString("hex").toUpperCase();

/** A 16-byte GUID: three little-endian fields, then eight bytes in order. */
const guidParts = (bytes: Buffer) => {
  const data1 = bytes.readUInt32LE(0).toString(16).padStart(8, "0");
  const data2 = bytes.readUInt16LE(4).toString(16).padStart(4, "0");
  const data3 = bytes.readUInt16LE(6).toString(16).padStart(4, "0");
  const data4 = bytes.subarray(8, 16).toString("hex");
  return {
    text: `${data1}-${data2}-${data3}-${data4.slice(0, 4)}-${data4.slice(4)}`.toUpperCase(),
    compact: `${data1}${data2}${data3}${data4}`.toUpperCase(),
  };
};

/** CodeView records identify the PDB or ELF build a module was linked from. */
const readCodeView = (
  file: MinidumpFile,
  record: LocationDescriptor,
): CodeView | null => {
  if (record.size < 4 || record.rva === 0) return null;
  const bytes = file.slice(record.rva, record.size, "CodeView record");
  const signature = bytes.toString("latin1", 0, 4);
  const cString = (from: number) => {
    const end = bytes.indexOf(0, from);
    return bytes.toString("utf8", from, end < 0 ? bytes.length : end);
  };
  if (signature === "RSDS" && bytes.length >= 24) {
    const guid = guidParts(bytes.subarray(4, 20));
    const age = bytes.readUInt32LE(20);
    return {
      format: "RSDS",
      pdb: cString(24),
      guid: guid.text,
      age,
      debugId: `${guid.compact}${age.toString(16).toUpperCase()}`,
    };
  }
  if (signature === "NB10" && bytes.length >= 16) {
    const timestamp = bytes.readUInt32LE(8);
    const age = bytes.readUInt32LE(12);
    return {
      format: "NB10",
      pdb: cString(16),
      signature: timestamp,
      age,
      debugId: `${timestamp.toString(16).toUpperCase()}${age.toString(16).toUpperCase()}`,
    };
  }
  // Breakpad writes 0x4270454c ('BpEL') as a little-endian integer.
  if (bytes.readUInt32LE(0) === 0x4270454c) {
    const buildId = bytes.subarray(4);
    const padded = Buffer.concat([buildId, Buffer.alloc(16)]).subarray(0, 16);
    return {
      format: "ELF build ID",
      buildId: buildId.toString("hex"),
      debugId: `${guidParts(padded).compact}0`,
    };
  }
  return { format: "unknown", signature: hexBytes(bytes.subarray(0, 4)) };
};

export const readModules = (file: MinidumpFile): RawModule[] | null => {
  const table = records(file, 4, 108);
  if (table === null) return null;
  return Array.from({ length: table.count }, (_, index) => {
    const at = table.at + index * 108;
    const fixed = file.u32(at + 24) === 0xfeef04bd;
    return {
      base: file.u64(at),
      size: file.u32(at + 8),
      checksum: file.u32(at + 12),
      timestamp: file.u32(at + 16),
      name: file.string(file.u32(at + 20)),
      fileVersion: fixed ? version(file.u32(at + 32), file.u32(at + 36)) : null,
      productVersion: fixed
        ? version(file.u32(at + 40), file.u32(at + 44))
        : null,
      codeView: readCodeView(file, location(file, at + 76)),
    };
  });
};

export const readUnloadedModules = (file: MinidumpFile) => {
  const stream = file.stream(14);
  if (stream === undefined) return null;
  const header = file.u32(stream.rva);
  const entry = file.u32(stream.rva + 4);
  const count = file.u32(stream.rva + 8);
  if (entry < 24 || header + count * entry > stream.size)
    throw new MinidumpFormatError(
      "UnloadedModuleList entries exceed the stream.",
    );
  return Array.from({ length: count }, (_, index) => {
    const at = stream.rva + header + index * entry;
    return {
      base: file.u64(at),
      size: file.u32(at + 8),
      timestamp: file.u32(at + 16),
      name: file.string(file.u32(at + 20)),
    };
  });
};

/** MemoryList: stacks and other ranges in small dumps. */
export const readMemoryList = (file: MinidumpFile): MemoryRange[] => {
  const list = records(file, 5, 16);
  if (list === null) return [];
  return Array.from({ length: list.count }, (_, index) => {
    const at = list.at + index * 16;
    return {
      start: file.u64(at),
      size: BigInt(file.u32(at + 8)),
      rva: file.u32(at + 12),
    };
  });
};

/** Memory64List: full-memory dumps store ranges back to back from BaseRva. */
export const readMemory64List = (file: MinidumpFile): MemoryRange[] => {
  const stream = file.stream(9);
  if (stream === undefined) return [];
  const count = Number(file.u64(stream.rva));
  let rva = Number(file.u64(stream.rva + 8));
  if (16 + count * 16 > stream.size)
    throw new MinidumpFormatError("Memory64List entries exceed the stream.");
  return Array.from({ length: count }, (_, index) => {
    const at = stream.rva + 16 + index * 16;
    const size = file.u64(at + 8);
    const range = { start: file.u64(at), size, rva };
    rva += Number(size);
    return range;
  });
};

export const readException = (file: MinidumpFile): RawException | null => {
  const stream = file.stream(6);
  if (stream === undefined) return null;
  if (stream.size < 168)
    throw new MinidumpFormatError("The Exception stream is truncated.");
  const at = stream.rva;
  const count = Math.min(file.u32(at + 32), 15);
  return {
    threadId: file.u32(at),
    code: file.u32(at + 8),
    flags: file.u32(at + 12),
    address: file.u64(at + 24),
    parameters: Array.from({ length: count }, (_, index) =>
      file.u64(at + 40 + index * 8),
    ),
    context: location(file, at + 160),
  };
};

export const readSystemInfo = (file: MinidumpFile): RawSystemInfo | null => {
  const stream = file.stream(7);
  if (stream === undefined) return null;
  if (stream.size < 56)
    throw new MinidumpFormatError("The SystemInfo stream is truncated.");
  const at = stream.rva;
  const architecture = file.u16(at);
  const csd = file.u32(at + 24);
  const vendor =
    architecture === 0 || architecture === 9
      ? file
          .slice(at + 32, 12, "CPU vendor")
          .toString("latin1")
          .replace(/\0+$/u, "")
      : "";
  return {
    architecture,
    processorLevel: file.u16(at + 2),
    processorRevision: file.u16(at + 4),
    processors: file.bytes.readUInt8(at + 6),
    productType: file.bytes.readUInt8(at + 7),
    major: file.u32(at + 8),
    minor: file.u32(at + 12),
    build: file.u32(at + 16),
    platform: file.u32(at + 20),
    csdVersion: csd === 0 ? null : file.string(csd) || null,
    cpuVendor: /^[\x20-\x7e]+$/u.test(vendor) ? vendor : null,
  };
};

export const readMiscInfo = (file: MinidumpFile) => {
  const stream = file.stream(15);
  if (stream === undefined || stream.size < 24) return null;
  const flags = file.u32(stream.rva + 4);
  return {
    processId: (flags & 1) === 1 ? file.u32(stream.rva + 8) : null,
    processCreateTime: (flags & 2) === 2 ? file.u32(stream.rva + 12) : null,
  };
};

export const readThreadNames = (file: MinidumpFile): Map<number, string> => {
  const names = new Map<number, string>();
  const table = records(file, 24, 12);
  if (table === null) return names;
  for (let index = 0; index < table.count; index += 1) {
    const at = table.at + index * 12;
    const rva = Number(file.u64(at + 4));
    const name = rva === 0 ? "" : file.string(rva);
    if (name.length > 0) names.set(file.u32(at), name);
  }
  return names;
};
