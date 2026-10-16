/** A binary whose headers cannot be mapped; scanning falls back to raw offsets. */
export class ImageLayoutError extends Error {}

/** One file-backed region with its load address. */
export interface ImageSection {
  readonly name: string;
  readonly fileOffset: number;
  readonly size: number;
  readonly address: bigint;
  readonly executable: boolean;
}

export interface ImageLayout {
  readonly format: "pe" | "elf" | "macho" | "raw";
  readonly architecture: string | null;
  /** Preferred image base; addresses below are absolute link-time addresses. */
  readonly imageBase: bigint | null;
  readonly sections: readonly ImageSection[];
}

const fail = (message: string): never => {
  throw new ImageLayoutError(message);
};

const need = (bytes: Buffer, offset: number, length: number, what: string) => {
  if (offset < 0 || length < 0 || offset + length > bytes.length)
    fail(`${what} lies outside the file.`);
};

const PE_MACHINES: Readonly<Record<number, string>> = {
  0x14c: "x86",
  0x8664: "amd64",
  0x1c4: "arm",
  0xaa64: "arm64",
};

const readPe = (bytes: Buffer): ImageLayout => {
  need(bytes, 0x3c, 4, "e_lfanew");
  const pe = bytes.readUInt32LE(0x3c);
  need(bytes, pe, 24, "PE header");
  if (bytes.readUInt32LE(pe) !== 0x4550) fail("Missing the PE signature.");
  const machine = bytes.readUInt16LE(pe + 4);
  const count = bytes.readUInt16LE(pe + 6);
  const optionalSize = bytes.readUInt16LE(pe + 20);
  const optional = pe + 24;
  need(bytes, optional, Math.max(optionalSize, 32), "optional header");
  const magic = bytes.readUInt16LE(optional);
  const imageBase =
    magic === 0x20b
      ? bytes.readBigUInt64LE(optional + 24)
      : magic === 0x10b
        ? BigInt(bytes.readUInt32LE(optional + 28))
        : fail(`Unknown PE optional header magic 0x${magic.toString(16)}.`);
  const table = optional + optionalSize;
  need(bytes, table, count * 40, "section table");
  const sections = Array.from({ length: count }, (_, index) => {
    const at = table + index * 40;
    const name = bytes.toString("latin1", at, at + 8).replace(/\0+$/u, "");
    const rva = bytes.readUInt32LE(at + 12);
    const rawSize = bytes.readUInt32LE(at + 16);
    const rawOffset = bytes.readUInt32LE(at + 20);
    const virtualSize = bytes.readUInt32LE(at + 8);
    const size = Math.min(
      rawSize,
      virtualSize === 0 ? rawSize : virtualSize,
      Math.max(0, bytes.length - rawOffset),
    );
    return {
      name,
      fileOffset: rawOffset,
      size,
      address: imageBase + BigInt(rva),
      executable: (bytes.readUInt32LE(at + 36) & 0x20000000) !== 0,
    };
  }).filter(({ size }) => size > 0);
  return {
    format: "pe",
    architecture: PE_MACHINES[machine] ?? `0x${machine.toString(16)}`,
    imageBase,
    sections,
  };
};

const ELF_MACHINES: Readonly<Record<number, string>> = {
  3: "x86",
  40: "arm",
  62: "amd64",
  183: "arm64",
  243: "riscv",
};

/** Width- and byte-order-aware field reads for one ELF image. */
const elfReader = (bytes: Buffer) => {
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  if ((bytes[4] !== 1 && !is64) || (bytes[5] !== 1 && bytes[5] !== 2))
    fail("Unsupported ELF class or byte order.");
  const u16 = (at: number) =>
    little ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at);
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const word = (at: number) =>
    is64
      ? little
        ? bytes.readBigUInt64LE(at)
        : bytes.readBigUInt64BE(at)
      : BigInt(u32(at));
  return { bytes, is64, u16, u32, word };
};

type ElfReader = ReturnType<typeof elfReader>;

const clampSize = (bytes: Buffer, offset: number, size: number) =>
  Math.min(size, Math.max(0, bytes.length - offset));

/** Allocated sections with names from the section-name string table. */
const elfSections = (elf: ElfReader): ImageSection[] => {
  const { bytes, is64, u16, u32, word } = elf;
  const shoff = Number(word(is64 ? 40 : 32));
  const shentsize = u16(is64 ? 58 : 46);
  const shnum = u16(is64 ? 60 : 48);
  const shstrndx = u16(is64 ? 62 : 50);
  if (shoff === 0 || shnum === 0 || shstrndx >= shnum) return [];
  const header = (index: number) => {
    const at = shoff + index * shentsize;
    need(bytes, at, shentsize, "section header");
    return {
      name: u32(at),
      type: u32(at + 4),
      flags: word(at + 8),
      address: word(is64 ? at + 16 : at + 12),
      offset: Number(word(is64 ? at + 24 : at + 16)),
      size: Number(word(is64 ? at + 32 : at + 20)),
    };
  };
  const strings = header(shstrndx);
  const nameAt = (offset: number) => {
    const at = strings.offset + offset;
    if (at >= bytes.length) return "";
    const end = bytes.indexOf(0, at);
    return bytes.toString("latin1", at, end < 0 ? bytes.length : end);
  };
  return Array.from({ length: shnum }, (_, index) => header(index))
    .filter(
      ({ type, address, size }) => type !== 8 && address !== 0n && size > 0,
    )
    .map((section) => ({
      name: nameAt(section.name),
      fileOffset: section.offset,
      size: clampSize(bytes, section.offset, section.size),
      address: section.address,
      executable: (section.flags & 4n) !== 0n,
    }));
};

/** PT_LOAD segments, for images without section headers. */
const elfSegments = (elf: ElfReader): ImageSection[] => {
  const { bytes, is64, u16, u32, word } = elf;
  const phoff = Number(word(is64 ? 32 : 28));
  const phentsize = u16(is64 ? 54 : 42);
  const phnum = u16(is64 ? 56 : 44);
  const segments: ImageSection[] = [];
  for (let index = 0; index < phnum; index += 1) {
    const at = phoff + index * phentsize;
    need(bytes, at, phentsize, "program header");
    if (u32(at) !== 1) continue;
    const offset = Number(word(is64 ? at + 8 : at + 4));
    segments.push({
      name: `LOAD${String(segments.length)}`,
      fileOffset: offset,
      size: clampSize(bytes, offset, Number(word(is64 ? at + 32 : at + 16))),
      address: word(is64 ? at + 16 : at + 8),
      executable: (u32(is64 ? at + 4 : at + 24) & 1) !== 0,
    });
  }
  return segments;
};

const readElf = (bytes: Buffer): ImageLayout => {
  need(bytes, 0, 52, "ELF header");
  const elf = elfReader(bytes);
  const sections = elfSections(elf);
  const machine = elf.u16(18);
  return {
    format: "elf",
    architecture: ELF_MACHINES[machine] ?? `0x${machine.toString(16)}`,
    imageBase: null,
    sections: sections.length > 0 ? sections : elfSegments(elf),
  };
};

const MACHO_CPUS: Readonly<Record<number, string>> = {
  0x01000007: "amd64",
  0x0100000c: "arm64",
};

/** Thin 64-bit little-endian Mach-O: LC_SEGMENT_64 sections. */
const readMacho = (bytes: Buffer): ImageLayout => {
  need(bytes, 0, 32, "Mach-O header");
  const cpu = bytes.readUInt32LE(4);
  const commands = bytes.readUInt32LE(16);
  const sections: ImageSection[] = [];
  let at = 32;
  let base: bigint | null = null;
  for (let index = 0; index < commands; index += 1) {
    need(bytes, at, 8, "load command");
    const command = bytes.readUInt32LE(at);
    const size = bytes.readUInt32LE(at + 4);
    if (size < 8) fail("Malformed Mach-O load command size.");
    if (command === 0x19) {
      need(bytes, at, 72, "LC_SEGMENT_64");
      const segment = bytes
        .toString("latin1", at + 8, at + 24)
        .replace(/\0+$/u, "");
      const vmaddr = bytes.readBigUInt64LE(at + 24);
      const fileoff = bytes.readBigUInt64LE(at + 40);
      if (segment === "__TEXT" && fileoff === 0n) base = vmaddr;
      const count = bytes.readUInt32LE(at + 64);
      need(bytes, at + 72, count * 80, "Mach-O sections");
      for (let entry = 0; entry < count; entry += 1) {
        const s = at + 72 + entry * 80;
        const type = bytes.readUInt32LE(s + 64) & 0xff;
        if (type === 0x1 || type === 0xc || type === 0x12) continue;
        const offset = bytes.readUInt32LE(s + 48);
        const length = Number(bytes.readBigUInt64LE(s + 40));
        sections.push({
          name: `${segment},${bytes.toString("latin1", s, s + 16).replace(/\0+$/u, "")}`,
          fileOffset: offset,
          size: Math.min(length, Math.max(0, bytes.length - offset)),
          address: bytes.readBigUInt64LE(s + 32),
          executable: (bytes.readUInt32LE(s + 64) & 0x80000400) !== 0,
        });
      }
    }
    at += size;
  }
  return {
    format: "macho",
    architecture: MACHO_CPUS[cpu] ?? `0x${cpu.toString(16)}`,
    imageBase: base,
    sections: sections.filter(({ size }) => size > 0),
  };
};

/** Map a PE, ELF or thin 64-bit Mach-O; anything else is raw bytes. */
export const readImageLayout = (bytes: Buffer): ImageLayout => {
  if (bytes.length >= 2 && bytes.readUInt16LE(0) === 0x5a4d)
    return readPe(bytes);
  if (bytes.length >= 4 && bytes.toString("latin1", 0, 4) === "\x7fELF")
    return readElf(bytes);
  if (bytes.length >= 4 && bytes.readUInt32LE(0) === 0xfeedfacf)
    return readMacho(bytes);
  return { format: "raw", architecture: null, imageBase: null, sections: [] };
};

/** The section holding a file offset, if any. */
export const sectionAtOffset = (
  layout: ImageLayout,
  offset: number,
): ImageSection | undefined =>
  layout.sections.find(
    ({ fileOffset, size }) =>
      offset >= fileOffset && offset < fileOffset + size,
  );

/** The section holding a load address, if any. */
export const sectionAtAddress = (
  layout: ImageLayout,
  address: bigint,
): ImageSection | undefined =>
  layout.sections.find(
    (section) =>
      address >= section.address &&
      address < section.address + BigInt(section.size),
  );
