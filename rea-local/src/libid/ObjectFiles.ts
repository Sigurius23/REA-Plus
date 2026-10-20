/**
 * Functions of relocatable object files (ELF `.o` and COFF `.obj`/`.o`),
 * with the byte ranges the linker rewrites. Those ranges become wildcards in
 * a signature; everything else must appear unchanged in a binary that
 * linked the object.
 */

export interface ObjectReference {
  /** Field offset within the function. */
  readonly offset: number;
  /** A PC-relative 32-bit field, so the linked target is P + 4 + disp. */
  readonly pcRelative: boolean;
  /** The function or external symbol the field refers to. */
  readonly symbol: string | null;
  /**
   * For a field into the object's own data: up to 64 bytes there, read at
   * the place P + 4 + disp will point to in the linked binary.
   */
  readonly data: Buffer | null;
}

export interface ObjectFunction {
  readonly name: string;
  readonly local: boolean;
  /** Section and offset in it: aliases share both, and a section keeps its layout when linked. */
  readonly section: number;
  readonly offset: number;
  readonly bytes: Buffer;
  /** Byte ranges [start, end) the linker may change. */
  readonly wildcards: readonly (readonly [number, number])[];
  readonly references: readonly ObjectReference[];
}

export interface RelocatableObject {
  readonly format: "elf" | "coff";
  readonly machine: string;
  readonly functions: readonly ObjectFunction[];
}

const MACHINES: Readonly<Record<number, string>> = {
  3: "x86",
  62: "x86-64",
  40: "arm",
  183: "aarch64",
};
const COFF_MACHINES: Readonly<Record<number, string>> = {
  0x14c: "x86",
  0x8664: "x86-64",
  0xaa64: "aarch64",
  0x1c4: "arm",
};
const DATA_BYTES = 64;

/** Relocations x86-64 linkers relax by rewriting the instruction before the field. */
const X64_RELAXED = new Set([9, 22, 41, 42]);
/** General- and local-dynamic TLS sequences relax into different instructions. */
const X64_TLS_SEQUENCE = new Set([19, 20]);
const X64_PC_RELATIVE = new Set([2, 4, 9, 22, 41, 42]);

interface Field {
  readonly size: number;
  readonly pcRelative: boolean;
  readonly before: number;
  readonly after: number;
}

const elfField = (machine: string, type: number): Field => {
  if (machine === "x86-64") {
    if (X64_TLS_SEQUENCE.has(type))
      return { size: 4, pcRelative: false, before: 4, after: 8 };
    return {
      size: type === 1 || type === 24 ? 8 : 4,
      pcRelative: X64_PC_RELATIVE.has(type),
      before: X64_RELAXED.has(type) ? 3 : 0,
      after: 0,
    };
  }
  if (machine === "x86")
    return {
      size: 4,
      pcRelative: type === 2 || type === 4,
      before: 0,
      after: 0,
    };
  // AArch64 and ARM encode targets inside 4-byte instructions; ABS64 is data.
  return { size: type === 257 ? 8 : 4, pcRelative: false, before: 0, after: 0 };
};

const coffField = (
  machine: string,
  type: number,
): Field & { readonly adjust: number } => {
  if (machine === "x86-64") {
    if (type >= 4 && type <= 9)
      return {
        size: 4,
        pcRelative: true,
        before: 0,
        after: 0,
        adjust: type - 4,
      };
    return {
      size: type === 1 ? 8 : type === 10 ? 2 : 4,
      pcRelative: false,
      before: 0,
      after: 0,
      adjust: 0,
    };
  }
  if (machine === "x86")
    return {
      size: type === 0xa ? 2 : 4,
      pcRelative: type === 0x14,
      before: 0,
      after: 0,
      adjust: 0,
    };
  return {
    size: type === 0xe ? 8 : 4,
    pcRelative: false,
    before: 0,
    after: 0,
    adjust: 0,
  };
};

class Reader {
  constructor(
    readonly data: Buffer,
    readonly wide: boolean,
  ) {}

  word(at: number): number {
    return this.wide
      ? Number(this.data.readBigUInt64LE(at))
      : this.data.readUInt32LE(at);
  }

  signedWord(at: number): number {
    return this.wide
      ? Number(this.data.readBigInt64LE(at))
      : this.data.readInt32LE(at);
  }
}

const cString = (data: Buffer, at: number): string => {
  const end = data.indexOf(0, at);
  return data.toString("latin1", at, end < 0 ? data.length : end);
};

const slice = (data: Buffer, at: number, length: number) =>
  at >= 0 && at <= data.length
    ? data.subarray(at, Math.min(data.length, at + length))
    : null;

interface ElfSection {
  readonly type: number;
  readonly flags: number;
  readonly offset: number;
  readonly size: number;
  readonly link: number;
  readonly info: number;
  readonly entsize: number;
}

interface ElfSymbol {
  readonly name: string;
  readonly type: number;
  readonly bind: number;
  readonly section: number;
  readonly value: number;
  readonly size: number;
}

const elfSections = (r: Reader): ElfSection[] => {
  const { data, wide } = r;
  const shoff = wide ? r.word(0x28) : data.readUInt32LE(0x20);
  const entsize = data.readUInt16LE(wide ? 0x3a : 0x2e);
  const count = data.readUInt16LE(wide ? 0x3c : 0x30);
  return Array.from({ length: count }, (_, index) => {
    const at = shoff + index * entsize;
    return wide
      ? {
          type: data.readUInt32LE(at + 4),
          flags: Number(data.readBigUInt64LE(at + 8)),
          offset: r.word(at + 0x18),
          size: r.word(at + 0x20),
          link: data.readUInt32LE(at + 0x28),
          info: data.readUInt32LE(at + 0x2c),
          entsize: r.word(at + 0x38),
        }
      : {
          type: data.readUInt32LE(at + 4),
          flags: data.readUInt32LE(at + 8),
          offset: data.readUInt32LE(at + 0x10),
          size: data.readUInt32LE(at + 0x14),
          link: data.readUInt32LE(at + 0x18),
          info: data.readUInt32LE(at + 0x1c),
          entsize: data.readUInt32LE(at + 0x24),
        };
  });
};

const elfSymbols = (
  r: Reader,
  sections: readonly ElfSection[],
): ElfSymbol[] => {
  const table = sections.find(({ type }) => type === 2);
  const strings = table === undefined ? undefined : sections[table.link];
  if (table === undefined || strings === undefined) return [];
  const size = r.wide ? 24 : 16;
  return Array.from({ length: Math.floor(table.size / size) }, (_, index) => {
    const at = table.offset + index * size;
    const info = r.data.readUInt8(at + (r.wide ? 4 : 12));
    return {
      name: cString(r.data, strings.offset + r.data.readUInt32LE(at)),
      type: info & 0xf,
      bind: info >> 4,
      section: r.data.readUInt16LE(at + (r.wide ? 6 : 14)),
      value: r.wide ? r.word(at + 8) : r.data.readUInt32LE(at + 4),
      size: r.wide ? r.word(at + 16) : r.data.readUInt32LE(at + 8),
    };
  });
};

/** One ELF relocation: offset in its section, symbol index, type, explicit addend. */
const elfRelocations = (r: Reader, section: ElfSection) => {
  const rela = section.type === 4;
  const size = section.entsize || (r.wide ? (rela ? 24 : 16) : rela ? 12 : 8);
  return Array.from({ length: Math.floor(section.size / size) }, (_, index) => {
    const at = section.offset + index * size;
    const info = r.word(at + (r.wide ? 8 : 4));
    return {
      offset: r.word(at),
      symbol: r.wide ? Math.floor(info / 2 ** 32) : info >>> 8,
      type: r.wide ? info % 2 ** 32 : info & 0xff,
      addend: rela ? r.signedWord(at + (r.wide ? 16 : 8)) : null,
    };
  });
};

interface ElfObject {
  readonly data: Buffer;
  readonly machine: string;
  readonly sections: readonly ElfSection[];
  readonly symbols: readonly ElfSymbol[];
  readonly relocations: ReadonlyMap<number, ReturnType<typeof elfRelocations>>;
}

/** What one relocation inside a function refers to, when its field is PC-relative. */
const elfReference = (
  object: ElfObject,
  section: ElfSection,
  relocation: ReturnType<typeof elfRelocations>[number],
  offset: number,
): ObjectReference | null => {
  const field = elfField(object.machine, relocation.type);
  const target = object.symbols[relocation.symbol];
  if (target === undefined || !field.pcRelative || field.size !== 4)
    return null;
  const addend =
    relocation.addend ??
    object.data.readInt32LE(section.offset + relocation.offset);
  const targetSection = object.sections[target.section];
  const isData =
    target.type === 3 || (target.type === 1 && targetSection !== undefined);
  const readable =
    isData && targetSection !== undefined && targetSection.type !== 8;
  return {
    offset,
    pcRelative: true,
    symbol: isData ? null : target.name,
    data: readable
      ? slice(
          object.data.subarray(
            targetSection.offset,
            targetSection.offset + targetSection.size,
          ),
          target.value + addend + 4,
          DATA_BYTES,
        )
      : null,
  };
};

const elfFunction = (
  object: ElfObject,
  symbol: ElfSymbol,
): ObjectFunction | null => {
  const section = object.sections[symbol.section];
  if (
    (symbol.type !== 2 && symbol.type !== 10) ||
    symbol.size === 0 ||
    section === undefined ||
    (section.flags & 0x4) === 0 ||
    section.type === 8
  )
    return null;
  const wildcards: [number, number][] = [];
  const references: ObjectReference[] = [];
  for (const relocation of object.relocations.get(symbol.section) ?? []) {
    const offset = relocation.offset - symbol.value;
    if (offset < 0 || offset >= symbol.size) continue;
    const field = elfField(object.machine, relocation.type);
    wildcards.push([offset - field.before, offset + field.size + field.after]);
    const reference = elfReference(object, section, relocation, offset);
    if (reference !== null) references.push(reference);
  }
  return {
    name: symbol.name,
    local: symbol.bind === 0,
    section: symbol.section,
    offset: symbol.value,
    bytes: object.data.subarray(
      section.offset + symbol.value,
      section.offset + symbol.value + symbol.size,
    ),
    wildcards,
    references,
  };
};

const readElf = (data: Buffer): RelocatableObject | null => {
  if (data.length < 0x40 || data.readUInt32BE(0) !== 0x7f454c46) return null;
  if (data.readUInt8(5) !== 1 || data.readUInt16LE(0x10) !== 1) return null;
  const r = new Reader(data, data.readUInt8(4) === 2);
  const machine = MACHINES[data.readUInt16LE(0x12)] ?? "unknown";
  const sections = elfSections(r);
  const relocations = new Map<number, ReturnType<typeof elfRelocations>>();
  for (const section of sections)
    if (section.type === 4 || section.type === 9)
      relocations.set(section.info, [
        ...(relocations.get(section.info) ?? []),
        ...elfRelocations(r, section),
      ]);
  const object: ElfObject = {
    data,
    machine,
    sections,
    symbols: elfSymbols(r, sections),
    relocations,
  };
  const functions = object.symbols
    .map((symbol) => elfFunction(object, symbol))
    .filter((fn) => fn !== null);
  return { format: "elf", machine, functions };
};

interface CoffSymbol {
  readonly name: string;
  readonly value: number;
  readonly section: number;
  readonly type: number;
  readonly storage: number;
}

const coffSymbols = (
  data: Buffer,
  pointer: number,
  count: number,
): (CoffSymbol | undefined)[] => {
  const strings = pointer + count * 18;
  const symbols: (CoffSymbol | undefined)[] = [];
  for (let index = 0; index < count; index += 1) {
    const at = pointer + index * 18;
    const name =
      data.readUInt32LE(at) === 0
        ? cString(data, strings + data.readUInt32LE(at + 4))
        : data.toString("latin1", at, at + 8).replace(/\0.*$/su, "");
    const aux = data.readUInt8(at + 17);
    symbols.push({
      name,
      value: data.readUInt32LE(at + 8),
      section: data.readInt16LE(at + 12),
      type: data.readUInt16LE(at + 14),
      storage: data.readUInt8(at + 16),
    });
    for (let skip = 0; skip < aux; skip += 1) symbols.push(undefined);
    index += aux;
  }
  return symbols;
};

const readCoff = (data: Buffer): RelocatableObject | null => {
  if (data.length < 20) return null;
  const machine = COFF_MACHINES[data.readUInt16LE(0)];
  if (machine === undefined || data.readUInt16LE(16) !== 0) return null;
  const sectionCount = data.readUInt16LE(2);
  const symbols = coffSymbols(
    data,
    data.readUInt32LE(8),
    data.readUInt32LE(12),
  );
  const sections = Array.from({ length: sectionCount }, (_, index) => {
    const at = 20 + index * 40;
    return {
      size: data.readUInt32LE(at + 16),
      offset: data.readUInt32LE(at + 20),
      relocations: data.readUInt32LE(at + 24),
      relocationCount: data.readUInt16LE(at + 32),
      characteristics: data.readUInt32LE(at + 36),
    };
  });
  const functions: ObjectFunction[] = [];
  sections.forEach((section, index) => {
    const executable = (section.characteristics & 0x20000020) !== 0;
    const uninitialized = (section.characteristics & 0x80) !== 0;
    if (!executable || uninitialized || section.offset === 0) return;
    const body = data.subarray(section.offset, section.offset + section.size);
    const starts = symbols
      .filter(
        (symbol): symbol is CoffSymbol =>
          symbol !== undefined &&
          symbol.section === index + 1 &&
          (symbol.type & 0x30) === 0x20 &&
          (symbol.storage === 2 || symbol.storage === 3),
      )
      .sort((a, b) => a.value - b.value);
    const relocations = Array.from(
      { length: section.relocationCount },
      (_, at) => {
        const base = section.relocations + at * 10;
        return {
          offset: data.readUInt32LE(base),
          symbol: data.readUInt32LE(base + 4),
          type: data.readUInt16LE(base + 8),
        };
      },
    );
    starts.forEach((symbol, position) => {
      const end = starts[position + 1]?.value ?? section.size;
      if (end <= symbol.value) return;
      const wildcards: [number, number][] = [];
      const references: ObjectReference[] = [];
      for (const relocation of relocations) {
        const offset = relocation.offset - symbol.value;
        if (offset < 0 || offset >= end - symbol.value) continue;
        const field = coffField(machine, relocation.type);
        wildcards.push([offset, offset + field.size]);
        const target = symbols[relocation.symbol];
        if (target === undefined || !field.pcRelative) continue;
        const targetSection = sections[target.section - 1];
        const isFunction =
          (target.type & 0x30) === 0x20 || target.section === 0;
        const addend = body.readInt32LE(relocation.offset);
        references.push({
          offset,
          pcRelative: true,
          symbol: isFunction ? target.name : null,
          data:
            !isFunction &&
            targetSection !== undefined &&
            targetSection.offset !== 0
              ? slice(
                  data.subarray(
                    targetSection.offset,
                    targetSection.offset + targetSection.size,
                  ),
                  target.value + addend - field.adjust,
                  DATA_BYTES,
                )
              : null,
        });
      }
      functions.push({
        name: symbol.name,
        local: symbol.storage === 3,
        section: index + 1,
        offset: symbol.value,
        bytes: body.subarray(symbol.value, end),
        wildcards,
        references,
      });
    });
  });
  return { format: "coff", machine, functions };
};

/** Read one relocatable object; null when it is neither ELF nor COFF, or malformed. */
export const readRelocatableObject = (
  data: Buffer,
): RelocatableObject | null => {
  try {
    return readElf(data) ?? readCoff(data);
  } catch {
    return null;
  }
};
