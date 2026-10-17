/**
 * A static library and a binary that linked it, built byte by byte: ELF64
 * x86-64 relocatable objects in a GNU `ar` archive, and an ELF executable
 * whose code holds those functions with every relocation resolved.
 *
 * The library holds the cases identification must settle:
 * - `checksum.o`: two routines and two wrappers whose bytes are identical
 *   but call different routines;
 * - `strings.o`: two functions identical but for the string they print;
 * - `twins.o`: two byte-identical functions without references, beside a
 *   unique one, and a function with an alias.
 */

export interface FixtureReference {
  readonly at: number;
  /** A function or external symbol, or a string in the member's .rodata. */
  readonly call?: string;
  readonly text?: string;
}

export interface FixtureFunction {
  readonly name: string;
  readonly aliases?: readonly string[];
  readonly local?: boolean;
  readonly body: readonly number[];
  readonly references?: readonly FixtureReference[];
}

export interface FixtureMember {
  readonly name: string;
  readonly functions: readonly FixtureFunction[];
}

const prologue = [0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5];
const epilogue = [0x5d, 0xc3];
const call = [0xe8, 0, 0, 0, 0];
/** lea rdi, [rip + disp32] */
const leaRdi = [0x48, 0x8d, 0x3d, 0, 0, 0, 0];

/** A body with a distinct run of arithmetic, so each routine is its own. */
const routine = (seed: number) => [
  ...prologue,
  0x89,
  0xf8, // mov eax, edi
  0x69,
  0xc0,
  seed,
  0x01,
  0x00,
  0x00, // imul eax, eax, seed+0x100
  0x35,
  seed,
  0xa5,
  0x5a,
  0x00, // xor eax, imm32
  0xc1,
  0xe0,
  (seed % 7) + 1, // shl eax, n
  0x01,
  0xf0, // add eax, esi
  ...epilogue,
];

/** A wrapper: prologue, a call, a fixed tail. */
const wrapper = [
  ...prologue,
  0x89,
  0xfb,
  0x89,
  0xd2,
  ...call,
  0x01,
  0xd8,
  0x83,
  0xc0,
  0x11,
  ...epilogue,
];
const WRAPPER_CALL = prologue.length + 4 + 1;

/** Prints a string: lea rdi, [rip + text]; call puts. */
const printer = [
  ...prologue,
  ...leaRdi,
  ...call,
  0x31,
  0xc0,
  0x48,
  0x83,
  0xc4,
  0x00,
  ...epilogue,
];
const PRINTER_TEXT = prologue.length + 3;
const PRINTER_CALL = prologue.length + leaRdi.length + 1;

const twin = [
  ...prologue,
  0x8b,
  0x47,
  0x08,
  0x2b,
  0x47,
  0x0c,
  0x0f,
  0xaf,
  0xc0,
  0x83,
  0xe8,
  0x07,
  ...epilogue,
];

export const LIBRARY_MEMBERS: readonly FixtureMember[] = [
  {
    name: "checksum.o",
    functions: [
      { name: "adler_update", body: routine(0x31) },
      { name: "crc_update", body: routine(0x47) },
      {
        name: "adler",
        body: wrapper,
        references: [{ at: WRAPPER_CALL, call: "adler_update" }],
      },
      {
        name: "crc",
        body: wrapper,
        references: [{ at: WRAPPER_CALL, call: "crc_update" }],
      },
    ],
  },
  {
    name: "strings.o",
    functions: [
      {
        name: "say_hello",
        body: printer,
        references: [
          { at: PRINTER_TEXT, text: "hello, world" },
          { at: PRINTER_CALL, call: "puts" },
        ],
      },
      {
        name: "say_goodbye",
        body: printer,
        references: [
          { at: PRINTER_TEXT, text: "goodbye, world" },
          { at: PRINTER_CALL, call: "puts" },
        ],
      },
    ],
  },
  {
    // A long name, so the archive needs GNU's long-name table.
    name: "twins_and_aliases_member.o",
    functions: [
      { name: "anchor_routine", body: routine(0x59), local: true },
      { name: "tell", body: twin },
      { name: "tell64", body: twin },
      {
        name: "stream_close",
        aliases: ["_IO_stream_close"],
        body: routine(0x6b),
      },
    ],
  },
];

const align = (value: number, to: number) => Math.ceil(value / to) * to;

class Strings {
  readonly parts: Buffer[] = [Buffer.from([0])];
  #size = 1;
  add(text: string): number {
    const at = this.#size;
    this.parts.push(Buffer.from(`${text}\0`, "latin1"));
    this.#size += text.length + 1;
    return at;
  }
  get buffer() {
    return Buffer.concat(this.parts);
  }
}

/** Function offsets in a member's .text and string offsets in its .rodata. */
export const memberLayout = (member: FixtureMember) => {
  const offsets = new Map<string, number>();
  let at = 0;
  for (const fn of member.functions) {
    at = align(at, 16);
    offsets.set(fn.name, at);
    at += fn.body.length;
  }
  const texts = new Map<string, number>();
  let rodata = 0;
  for (const fn of member.functions)
    for (const { text } of fn.references ?? [])
      if (text !== undefined && !texts.has(text)) {
        texts.set(text, rodata);
        rodata += text.length + 1;
      }
  const text = Buffer.alloc(at, 0x90);
  for (const fn of member.functions)
    Buffer.from(fn.body).copy(text, offsets.get(fn.name) ?? 0);
  const strings = Buffer.alloc(rodata);
  for (const [value, offset] of texts)
    strings.write(`${value}\0`, offset, "latin1");
  return { offsets, texts, text, rodata: strings };
};

/** One ELF64 x86-64 relocatable object. */
interface ElfSection {
  readonly name: string;
  readonly type: number;
  readonly flags: number;
  readonly data: Buffer;
  readonly link: number;
  readonly info: number;
  readonly entsize: number;
}

type Sym = {
  name: number;
  info: number;
  shndx: number;
  value: number;
  size: number;
};

/** Symbols: null, the .rodata section, local functions, then globals and externs. */
const objectSymbols = (
  member: FixtureMember,
  offsets: ReadonlyMap<string, number>,
) => {
  const names = new Strings();
  const locals: Sym[] = [{ name: 0, info: 3, shndx: 2, value: 0, size: 0 }];
  const globals: Sym[] = [];
  for (const fn of member.functions)
    for (const name of [fn.name, ...(fn.aliases ?? [])])
      (fn.local === true ? locals : globals).push({
        name: names.add(name),
        info: ((fn.local === true ? 0 : 1) << 4) | 2,
        shndx: 1,
        value: offsets.get(fn.name) ?? 0,
        size: fn.body.length,
      });
  const externs = new Set(
    member.functions.flatMap(({ references }) =>
      (references ?? []).flatMap(({ call: target }) =>
        target === undefined || offsets.has(target) ? [] : [target],
      ),
    ),
  );
  for (const name of externs)
    globals.push({
      name: names.add(name),
      info: 0x10,
      shndx: 0,
      value: 0,
      size: 0,
    });
  const symbols = [
    { name: 0, info: 0, shndx: 0, value: 0, size: 0 },
    ...locals,
    ...globals,
  ];
  const text = names.buffer;
  const index = (name: string) =>
    symbols.findIndex(
      (symbol, at) =>
        at > 0 &&
        symbol.name !== 0 &&
        text.toString("latin1", symbol.name, text.indexOf(0, symbol.name)) ===
          name,
    );
  const table = Buffer.concat(
    symbols.map((symbol) => {
      const entry = Buffer.alloc(24);
      entry.writeUInt32LE(symbol.name, 0);
      entry.writeUInt8(symbol.info, 4);
      entry.writeUInt16LE(symbol.shndx, 6);
      entry.writeBigUInt64LE(BigInt(symbol.value), 8);
      entry.writeBigUInt64LE(BigInt(symbol.size), 16);
      return entry;
    }),
  );
  return { table, strings: text, firstGlobal: 1 + locals.length, index };
};

/** RELA entries: PLT32 calls to symbols, PC32 string loads against .rodata. */
const objectRelocations = (
  member: FixtureMember,
  layout: ReturnType<typeof memberLayout>,
  symbolIndex: (name: string) => number,
): Buffer =>
  Buffer.concat(
    member.functions.flatMap((fn) =>
      (fn.references ?? []).map((reference) => {
        const entry = Buffer.alloc(24);
        entry.writeBigUInt64LE(
          BigInt((layout.offsets.get(fn.name) ?? 0) + reference.at),
          0,
        );
        if (reference.text !== undefined) {
          entry.writeBigUInt64LE((1n << 32n) | 2n, 8);
          entry.writeBigInt64LE(
            BigInt((layout.texts.get(reference.text) ?? 0) - 4),
            16,
          );
        } else {
          entry.writeBigUInt64LE(
            (BigInt(symbolIndex(reference.call ?? "")) << 32n) | 4n,
            8,
          );
          entry.writeBigInt64LE(-4n, 16);
        }
        return entry;
      }),
    ),
  );

/** Lay sections out after the header, then their headers, with .shstrtab last. */
const writeRelocatable = (sections: readonly ElfSection[]): Buffer => {
  const sectionNames = new Strings();
  const nameOffsets = [...sections.map(({ name }) => name), ".shstrtab"].map(
    (name) => sectionNames.add(name),
  );
  const all: ElfSection[] = [
    ...sections,
    {
      name: ".shstrtab",
      type: 3,
      flags: 0,
      data: sectionNames.buffer,
      link: 0,
      info: 0,
      entsize: 0,
    },
  ];
  let at = 64;
  const placed = all.map((section) => {
    at = align(at, 8);
    const offset = at;
    at += section.data.length;
    return offset;
  });
  const shoff = align(at, 8);
  const file = Buffer.alloc(shoff + 64 * (all.length + 1));
  file.writeUInt32BE(0x7f454c46, 0);
  file.writeUInt8(2, 4);
  file.writeUInt8(1, 5);
  file.writeUInt8(1, 6);
  file.writeUInt16LE(1, 0x10);
  file.writeUInt16LE(62, 0x12);
  file.writeUInt32LE(1, 0x14);
  file.writeBigUInt64LE(BigInt(shoff), 0x28);
  file.writeUInt16LE(64, 0x34);
  file.writeUInt16LE(64, 0x3a);
  file.writeUInt16LE(all.length + 1, 0x3c);
  file.writeUInt16LE(all.length, 0x3e);
  all.forEach((section, index) => {
    section.data.copy(file, placed[index]);
    const header = shoff + 64 * (index + 1);
    file.writeUInt32LE(nameOffsets[index] ?? 0, header);
    file.writeUInt32LE(section.type, header + 4);
    file.writeBigUInt64LE(BigInt(section.flags), header + 8);
    file.writeBigUInt64LE(BigInt(placed[index] ?? 0), header + 0x18);
    file.writeBigUInt64LE(BigInt(section.data.length), header + 0x20);
    file.writeUInt32LE(section.link, header + 0x28);
    file.writeUInt32LE(section.info, header + 0x2c);
    file.writeBigUInt64LE(1n, header + 0x30);
    file.writeBigUInt64LE(BigInt(section.entsize), header + 0x38);
  });
  return file;
};

/** One ELF64 x86-64 relocatable object. */
export const elfObject = (member: FixtureMember): Buffer => {
  const layout = memberLayout(member);
  const symbols = objectSymbols(member, layout.offsets);
  const section = (
    name: string,
    type: number,
    data: Buffer,
    extra: Partial<ElfSection> = {},
  ): ElfSection => ({
    name,
    type,
    flags: 0,
    data,
    link: 0,
    info: 0,
    entsize: 0,
    ...extra,
  });
  return writeRelocatable([
    section(".text", 1, layout.text, { flags: 6 }),
    section(".rodata", 1, layout.rodata, { flags: 2 }),
    section(".symtab", 2, symbols.table, {
      link: 4,
      info: symbols.firstGlobal,
      entsize: 24,
    }),
    section(".strtab", 3, symbols.strings),
    section(".rela.text", 4, objectRelocations(member, layout, symbols.index), {
      link: 3,
      info: 1,
      entsize: 24,
    }),
  ]);
};

/** A GNU `ar` archive with a long-name table and an empty symbol index. */
export const gnuArchive = (
  members: readonly { name: string; data: Buffer }[],
): Buffer => {
  const header = (name: string, size: number) => {
    const fields = `${name.padEnd(16)}${"0".padEnd(12)}${"0".padEnd(6)}${"0".padEnd(6)}${"644".padEnd(8)}${String(size).padEnd(10)}\`\n`;
    return Buffer.from(fields, "latin1");
  };
  const pad = (data: Buffer) =>
    data.length % 2 === 0 ? data : Buffer.concat([data, Buffer.from("\n")]);
  let longNames = "";
  const named = members.map(({ name, data }) => {
    if (name.length < 16) return { field: `${name}/`, data };
    const field = `/${String(longNames.length)}`;
    longNames += `${name}/\n`;
    return { field, data };
  });
  const parts: Buffer[] = [
    Buffer.from("!<arch>\n", "latin1"),
    header("/", 4),
    Buffer.alloc(4),
  ];
  if (longNames.length > 0)
    parts.push(
      header("//", longNames.length),
      pad(Buffer.from(longNames, "latin1")),
    );
  for (const { field, data } of named)
    parts.push(header(field, data.length), pad(data));
  return Buffer.concat(parts);
};

export const fixtureLibrary = (): Buffer =>
  gnuArchive(
    LIBRARY_MEMBERS.map((member) => ({
      name: member.name,
      data: elfObject(member),
    })),
  );

/**
 * An ELF executable that linked every member: each member's .text at its
 * own place with unrelated code between, references resolved, strings in a
 * read-only segment, and `puts` as a stub.
 */
export const fixtureExecutable = () => {
  const base = 0x400000;
  const textAddress = base + 0x1000;
  const rodataAddress = base + 0x3000;
  const layouts = LIBRARY_MEMBERS.map(memberLayout);
  const filler = Buffer.from([
    0x0f, 0x0b, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x31, 0xc0, 0xc3,
    0xcc, 0xcc, 0xcc, 0xcc,
  ]);
  let at = 0x40;
  const memberText: number[] = [];
  const memberRodata: number[] = [];
  let rodataSize = 0;
  for (const layout of layouts) {
    at = align(at, 16) + 0x20;
    memberText.push(at);
    at += layout.text.length;
    memberRodata.push(rodataSize);
    rodataSize += layout.rodata.length + 3;
  }
  const putsAt = align(at, 16) + 0x10;
  const text = Buffer.alloc(putsAt + 16, 0xcc);
  for (let fill = 0; fill + filler.length <= text.length; fill += 0x200)
    filler.copy(text, fill);
  Buffer.from([0x31, 0xc0, 0xc3]).copy(text, putsAt);
  const rodata = Buffer.alloc(rodataSize);
  const symbols = new Map<string, number>([["puts", textAddress + putsAt]]);
  LIBRARY_MEMBERS.forEach((member, index) => {
    const layout = layouts[index];
    if (layout === undefined) return;
    layout.text.copy(text, memberText[index]);
    layout.rodata.copy(rodata, memberRodata[index]);
    for (const fn of member.functions)
      for (const name of [fn.name, ...(fn.aliases ?? [])])
        symbols.set(
          name,
          textAddress +
            (memberText[index] ?? 0) +
            (layout.offsets.get(fn.name) ?? 0),
        );
  });
  LIBRARY_MEMBERS.forEach((member, index) => {
    const layout = layouts[index];
    if (layout === undefined) return;
    for (const fn of member.functions)
      for (const reference of fn.references ?? []) {
        const field =
          (memberText[index] ?? 0) +
          (layout.offsets.get(fn.name) ?? 0) +
          reference.at;
        const target =
          reference.text !== undefined
            ? rodataAddress +
              (memberRodata[index] ?? 0) +
              (layout.texts.get(reference.text) ?? 0)
            : (symbols.get(reference.call ?? "") ?? 0);
        text.writeInt32LE(target - (textAddress + field + 4), field);
      }
  });
  const textOffset = 0x1000;
  const rodataOffset = 0x3000;
  const file = Buffer.alloc(rodataOffset + rodata.length);
  file.writeUInt32BE(0x7f454c46, 0);
  file.writeUInt8(2, 4);
  file.writeUInt8(1, 5);
  file.writeUInt8(1, 6);
  file.writeUInt16LE(2, 0x10);
  file.writeUInt16LE(62, 0x12);
  file.writeUInt32LE(1, 0x14);
  file.writeBigUInt64LE(BigInt(textAddress), 0x18);
  file.writeBigUInt64LE(64n, 0x20);
  file.writeUInt16LE(64, 0x34);
  file.writeUInt16LE(56, 0x36);
  file.writeUInt16LE(2, 0x38);
  const segment = (
    index: number,
    offset: number,
    address: number,
    size: number,
    flags: number,
  ) => {
    const header = 64 + index * 56;
    file.writeUInt32LE(1, header);
    file.writeUInt32LE(flags, header + 4);
    file.writeBigUInt64LE(BigInt(offset), header + 8);
    file.writeBigUInt64LE(BigInt(address), header + 0x10);
    file.writeBigUInt64LE(BigInt(address), header + 0x18);
    file.writeBigUInt64LE(BigInt(size), header + 0x20);
    file.writeBigUInt64LE(BigInt(size), header + 0x28);
    file.writeBigUInt64LE(0x1000n, header + 0x30);
  };
  segment(0, textOffset, textAddress, text.length, 5);
  segment(1, rodataOffset, rodataAddress, rodata.length, 4);
  text.copy(file, textOffset);
  rodata.copy(file, rodataOffset);
  return { file, symbols };
};
