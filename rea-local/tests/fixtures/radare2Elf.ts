/**
 * Deterministic x86-64 ELF executable for radare2 provider tests.
 *
 * One read/execute PT_LOAD maps the whole file at 0x400000 and a second,
 * read/write PT_LOAD maps zero-filled `.bss`. `.text` holds a three-function
 * call chain and `.rodata` one referenced string, with complete symbol and
 * section tables:
 *
 *   _start:     call check_key; mov edi, eax; mov eax, 60; syscall
 *   check_key:  lea rsi, [rip + secret]; call helper; ret
 *   helper:     lea eax, [rdi + rdi*2 + 1]; ret
 */
export const RADARE2_ELF_BASE = 0x400000;
export const RADARE2_ELF_SECRET = "SECRET-KEY-42";

const TEXT_OFFSET = 0x100;
const START = TEXT_OFFSET;
const CHECK_KEY = START + 14;
const HELPER = CHECK_KEY + 13;
const TEXT_END = HELPER + 5;
const RODATA_OFFSET = 0x140;
const SYMTAB_OFFSET = 0x180;
const BSS_ADDRESS = 0x500000;
const BSS_SIZE = 0x40;

/** Virtual addresses and file offsets a correct loader must report. */
export const RADARE2_ELF_LAYOUT = Object.freeze({
  start: RADARE2_ELF_BASE + START,
  startCall: RADARE2_ELF_BASE + START,
  checkKey: RADARE2_ELF_BASE + CHECK_KEY,
  checkKeyLea: RADARE2_ELF_BASE + CHECK_KEY,
  checkKeyCall: RADARE2_ELF_BASE + CHECK_KEY + 7,
  helper: RADARE2_ELF_BASE + HELPER,
  helperOffset: HELPER,
  helperBytes: "8d447f01c3",
  secret: RADARE2_ELF_BASE + RODATA_OFFSET,
  bss: BSS_ADDRESS,
  textStart: RADARE2_ELF_BASE + TEXT_OFFSET,
  textEnd: RADARE2_ELF_BASE + TEXT_END,
});

const rel32 = (from: number, to: number): number[] => {
  const buffer = Buffer.alloc(4);
  buffer.writeInt32LE(to - from);
  return [...buffer];
};

const TEXT = Buffer.from([
  // _start
  0xe8,
  ...rel32(START + 5, CHECK_KEY),
  0x89,
  0xc7,
  0xb8,
  0x3c,
  0x00,
  0x00,
  0x00,
  0x0f,
  0x05,
  // check_key
  0x48,
  0x8d,
  0x35,
  ...rel32(CHECK_KEY + 7, RODATA_OFFSET),
  0xe8,
  ...rel32(CHECK_KEY + 12, HELPER),
  0xc3,
  // helper
  0x8d,
  0x44,
  0x7f,
  0x01,
  0xc3,
]);
const RODATA = Buffer.from(`${RADARE2_ELF_SECRET}\0`, "utf8");

const stringTable = (names: readonly string[]) => {
  const offsets = new Map<string, number>();
  let size = 1;
  for (const name of names) {
    offsets.set(name, size);
    size += Buffer.byteLength(name) + 1;
  }
  return {
    bytes: Buffer.from(`\0${names.map((name) => `${name}\0`).join("")}`),
    offset: (name: string) => offsets.get(name) ?? 0,
  };
};

/** Write little-endian fields at byte offsets relative to `base`. */
const writeFields = (
  file: Buffer,
  base: number,
  fields: readonly (readonly [
    offset: number,
    bytes: 1 | 2 | 4 | 8,
    value: number,
  ])[],
): void => {
  for (const [offset, bytes, value] of fields) {
    if (bytes === 8) file.writeBigUInt64LE(BigInt(value), base + offset);
    else file.writeUIntLE(value, base + offset, bytes);
  }
};

const SYMBOLS = [
  // name, st_info, section index, value, size
  ["check_key", 0x02, 1, RADARE2_ELF_BASE + CHECK_KEY, 13],
  ["helper", 0x02, 1, RADARE2_ELF_BASE + HELPER, 5],
  ["secret", 0x01, 2, RADARE2_ELF_BASE + RODATA_OFFSET, RODATA.length],
  ["_start", 0x12, 1, RADARE2_ELF_BASE + START, 14],
] as const;

/** Build the fixture bytes; every call returns an identical buffer. */
export const createRadare2Elf = (): Buffer => {
  const names = stringTable(SYMBOLS.map(([name]) => name));
  const symtab = Buffer.alloc(24 * (SYMBOLS.length + 1));
  SYMBOLS.forEach(([name, info, section, value, size], index) =>
    writeFields(symtab, 24 * (index + 1), [
      [0, 4, names.offset(name)],
      [4, 1, info],
      [6, 2, section],
      [8, 8, value],
      [16, 8, size],
    ]),
  );
  const strtabOffset = SYMTAB_OFFSET + symtab.length;
  const sectionNames = stringTable([
    ".text",
    ".rodata",
    ".bss",
    ".symtab",
    ".strtab",
    ".shstrtab",
  ]);
  const shstrtabOffset = strtabOffset + names.bytes.length;
  const headersOffset =
    Math.ceil((shstrtabOffset + sectionNames.bytes.length) / 8) * 8;
  // name, type, flags, address, offset, size, link, info, align, entry size
  const sections = [
    [
      ".text",
      1,
      0x6,
      RADARE2_ELF_BASE + TEXT_OFFSET,
      TEXT_OFFSET,
      TEXT.length,
      0,
      0,
      16,
      0,
    ],
    [
      ".rodata",
      1,
      0x2,
      RADARE2_ELF_BASE + RODATA_OFFSET,
      RODATA_OFFSET,
      RODATA.length,
      0,
      0,
      1,
      0,
    ],
    [".bss", 8, 0x3, BSS_ADDRESS, 0, BSS_SIZE, 0, 0, 16, 0],
    [
      ".symtab",
      2,
      0,
      0,
      SYMTAB_OFFSET,
      symtab.length,
      5,
      SYMBOLS.length,
      8,
      24,
    ],
    [".strtab", 3, 0, 0, strtabOffset, names.bytes.length, 0, 0, 1, 0],
    [
      ".shstrtab",
      3,
      0,
      0,
      shstrtabOffset,
      sectionNames.bytes.length,
      0,
      0,
      1,
      0,
    ],
  ] as const;
  const fileSize = headersOffset + (sections.length + 1) * 64;
  const file = Buffer.alloc(fileSize);

  file.write("\x7fELF", 0, "latin1");
  // ELFCLASS64, little endian, EV_CURRENT; ET_EXEC for EM_X86_64.
  writeFields(file, 0, [
    [4, 1, 2],
    [5, 1, 1],
    [6, 1, 1],
    [16, 2, 2],
    [18, 2, 62],
    [20, 4, 1],
    [24, 8, RADARE2_ELF_BASE + START],
    [32, 8, 64],
    [40, 8, headersOffset],
    [52, 2, 64],
    [54, 2, 56],
    [56, 2, 2],
    [58, 2, 64],
    [60, 2, sections.length + 1],
    [62, 2, sections.length],
  ]);
  // PT_LOAD r-x for the file image, then PT_LOAD rw- for zero-filled .bss.
  const loads = [
    [5, 0, RADARE2_ELF_BASE, fileSize, fileSize],
    [6, 0, BSS_ADDRESS, 0, BSS_SIZE],
  ] as const;
  loads.forEach(([flags, offset, address, fileBytes, memoryBytes], index) =>
    writeFields(file, 64 + index * 56, [
      [0, 4, 1],
      [4, 4, flags],
      [8, 8, offset],
      [16, 8, address],
      [24, 8, address],
      [32, 8, fileBytes],
      [40, 8, memoryBytes],
      [48, 8, 0x1000],
    ]),
  );
  TEXT.copy(file, TEXT_OFFSET);
  RODATA.copy(file, RODATA_OFFSET);
  symtab.copy(file, SYMTAB_OFFSET);
  names.bytes.copy(file, strtabOffset);
  sectionNames.bytes.copy(file, shstrtabOffset);
  sections.forEach(
    (
      [name, type, flags, address, offset, size, link, info, align, entry],
      index,
    ) =>
      writeFields(file, headersOffset + (index + 1) * 64, [
        [0, 4, sectionNames.offset(name)],
        [4, 4, type],
        [8, 8, flags],
        [16, 8, address],
        [24, 8, offset],
        [32, 8, size],
        [40, 4, link],
        [44, 4, info],
        [48, 8, align],
        [56, 8, entry],
      ]),
  );
  return file;
};
