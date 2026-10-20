/**
 * Deterministic Unity IL2CPP build pair for r2unity adapter tests.
 *
 * `createIl2CppMetadata` writes a wire-version 29 `global-metadata.dat`
 * (Unity 2022.x layout: 31 offset/size header pairs, data from 0x100) with
 * two images, eleven types, eight methods, three fields, six string literals,
 * one P/Invoke declaration and one `[MonoPInvokeCallback]` method.
 *
 * `createIl2CppGameAssembly` writes the matching x86-64 `GameAssembly.so`
 * stand-in: `g_CodeRegistration` points at a codeGenModules array whose
 * Assembly-CSharp module lists one native stub per method (zero for the
 * abstract interface method), exactly as IL2CPP's generated registration does.
 */

const u32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value >>> 0);
  return bytes;
};
const i32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeInt32LE(value);
  return bytes;
};
const u16 = (value: number): Buffer => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
};
const u64 = (value: number): Buffer => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
};

/** Interned NUL-terminated identifier pool; offset 0 is the empty string. */
class StringPool {
  #bytes: Buffer[] = [Buffer.from([0])];
  #size = 1;
  readonly #offsets = new Map<string, number>([["", 0]]);

  offset(value: string): number {
    const known = this.#offsets.get(value);
    if (known !== undefined) return known;
    const offset = this.#size;
    const bytes = Buffer.from(`${value}\0`, "utf8");
    this.#bytes.push(bytes);
    this.#size += bytes.length;
    this.#offsets.set(value, offset);
    return offset;
  }

  bytes(): Buffer {
    return Buffer.concat(this.#bytes);
  }
}

interface FixtureMethod {
  readonly name: string;
  readonly returnType: number;
  readonly flags: number;
  readonly parameters: readonly (readonly [name: string, type: number])[];
  /** Native stub slot in `.text`, or null for a method without code. */
  readonly stub: number | null;
}

interface FixtureType {
  readonly namespace: string;
  readonly name: string;
  readonly parent: number;
  readonly flags: number;
  readonly fields?: readonly (readonly [name: string, type: number])[];
  readonly methods?: readonly FixtureMethod[];
  readonly interfaces?: readonly number[];
}

// byvalTypeIndex equals the type's position, so field, parameter, return and
// parent references are plain type indices.
const VOID = 4;
const STRING = 1;
const INT32 = 2;
const BOOLEAN = 3;
const OBJECT = 0;
const PUBLIC_CTOR = 0x1886;

const TYPES: readonly FixtureType[] = [
  { namespace: "System", name: "Object", parent: -1, flags: 0x2001 },
  { namespace: "System", name: "String", parent: OBJECT, flags: 0x2101 },
  { namespace: "System", name: "Int32", parent: OBJECT, flags: 0x2109 },
  { namespace: "System", name: "Boolean", parent: OBJECT, flags: 0x2109 },
  { namespace: "System", name: "Void", parent: OBJECT, flags: 0x2109 },
  { namespace: "System", name: "Attribute", parent: OBJECT, flags: 0x2081 },
  { namespace: "", name: "<Module>", parent: -1, flags: 0 },
  {
    namespace: "AOT",
    name: "MonoPInvokeCallbackAttribute",
    parent: 5,
    flags: 0x100001,
    methods: [
      {
        name: ".ctor",
        returnType: VOID,
        flags: PUBLIC_CTOR,
        parameters: [],
        stub: 0,
      },
    ],
  },
  {
    namespace: "Game",
    name: "IDamageable",
    parent: -1,
    flags: 0xa1,
    methods: [
      {
        name: "TakeDamage",
        returnType: VOID,
        flags: 0x5c6,
        parameters: [["amount", INT32]],
        stub: null,
      },
    ],
  },
  {
    namespace: "Game.Licensing",
    name: "LicenseCheck",
    parent: OBJECT,
    flags: 0x100181,
    fields: [["SecretKey", STRING]],
    methods: [
      {
        name: "Verify",
        returnType: BOOLEAN,
        flags: 0x96,
        parameters: [["candidate", STRING]],
        stub: 1,
      },
      {
        name: "NativeHash",
        returnType: INT32,
        flags: 0x2091,
        parameters: [["value", INT32]],
        stub: 2,
      },
    ],
  },
  {
    namespace: "Game",
    name: "Player",
    parent: OBJECT,
    flags: 0x100001,
    interfaces: [8],
    fields: [
      ["health", INT32],
      ["playerName", STRING],
    ],
    methods: [
      {
        name: "TakeDamage",
        returnType: VOID,
        flags: 0x1e6,
        parameters: [["amount", INT32]],
        stub: 3,
      },
      {
        name: "get_Health",
        returnType: INT32,
        flags: 0x886,
        parameters: [],
        stub: 4,
      },
      {
        name: "OnNativeEvent",
        returnType: VOID,
        flags: 0x91,
        parameters: [["code", INT32]],
        stub: 5,
      },
      {
        name: ".ctor",
        returnType: VOID,
        flags: PUBLIC_CTOR,
        parameters: [],
        stub: 6,
      },
    ],
  },
];

const IMAGES = [
  {
    name: "mscorlib.dll",
    assembly: "mscorlib",
    version: [4, 0, 0, 0],
    publicKeyToken: "b77a5c561934e089",
    typeStart: 0,
    typeCount: 6,
  },
  {
    name: "Assembly-CSharp.dll",
    assembly: "Assembly-CSharp",
    version: [1, 2, 3, 4],
    publicKeyToken: "0000000000000000",
    typeStart: 6,
    typeCount: 5,
  },
] as const;

/** Literal bytes, including escapes r2unity must render and REA+ must undo. */
export const IL2CPP_STRING_LITERALS: readonly Buffer[] = [
  Buffer.from("SECRET-KEY-42", "utf8"),
  Buffer.from("https://license.example.invalid/v1/verify", "utf8"),
  Buffer.from('Grüße, "Spieler"\n', "utf8"),
  Buffer.alloc(0),
  Buffer.from("C:\\Games\\Save\t1", "utf8"),
  // A lone UTF-16 surrogate encoded as three bytes is not valid UTF-8.
  Buffer.from([0x41, 0xed, 0xa0, 0x80, 0x01, 0x42]),
];

const TEXT_ADDRESS = 0x401000;
const DATA_ADDRESS = 0x402000;
const STUB_SIZE = 16;

/** Facts a correct reader must report for this pair. */
export const IL2CPP_FIXTURE = Object.freeze({
  wireVersion: 29,
  types: TYPES.length,
  methods: TYPES.reduce((sum, type) => sum + (type.methods?.length ?? 0), 0),
  fields: TYPES.reduce((sum, type) => sum + (type.fields?.length ?? 0), 0),
  codeRegistration: DATA_ADDRESS,
  codeGenModules: DATA_ADDRESS + 0x100,
  stub: (slot: number) => TEXT_ADDRESS + slot * STUB_SIZE,
  pinvokeToken: 0x06000004,
  reversePinvokeToken: 0x06000007,
});

const methodRows = () =>
  TYPES.flatMap((type, typeIndex) =>
    (type.methods ?? []).map((method) => ({ ...method, typeIndex })),
  );

/** Image owning a type; IL2CPP tokens count from 1 within each image. */
const imageOf = (typeIndex: number): 0 | 1 =>
  typeIndex < IMAGES[1].typeStart ? 0 : 1;

/** Il2CppTypeDefinition for wire version 29 (88 bytes). */
const typeRow = (
  strings: StringPool,
  type: FixtureType,
  typeIndex: number,
  starts: { field: number; method: number; interface: number },
): Buffer => {
  const methods = type.methods?.length ?? 0;
  const fields = type.fields?.length ?? 0;
  const interfaces = type.interfaces?.length ?? 0;
  return Buffer.concat([
    u32(strings.offset(type.name)),
    u32(strings.offset(type.namespace)),
    i32(typeIndex),
    i32(-1),
    i32(type.parent),
    i32(-1),
    i32(-1),
    u32(type.flags),
    i32(fields === 0 ? -1 : starts.field),
    i32(methods === 0 ? -1 : starts.method),
    i32(-1),
    i32(-1),
    i32(-1),
    i32(interfaces === 0 ? -1 : starts.interface),
    i32(-1),
    i32(-1),
    ...[methods, 0, fields, 0, 0, 0, interfaces, 0].map(u16),
    u32(0),
    u32(0x02000001 + typeIndex - IMAGES[imageOf(typeIndex)].typeStart),
  ]);
};

/** Row encoders for the wire-version 29 tables r2unity and IL2CPP read. */
const encodeTables = (strings: StringPool) => {
  const methods: Buffer[] = [];
  const parameters: Buffer[] = [];
  const fields: Buffer[] = [];
  const types: Buffer[] = [];
  const interfaces: Buffer[] = [];
  const tokens = [0, 0];
  TYPES.forEach((type, typeIndex) => {
    const starts = {
      field: fields.length,
      method: methods.length,
      interface: interfaces.length,
    };
    const image = imageOf(typeIndex);
    for (const method of type.methods ?? []) {
      tokens[image] = (tokens[image] ?? 0) + 1;
      methods.push(
        Buffer.concat([
          u32(strings.offset(method.name)),
          i32(typeIndex),
          i32(method.returnType),
          i32(parameters.length),
          i32(-1),
          u32(0x06000000 + (tokens[image] ?? 0)),
          u16(method.flags),
          u16(0),
          u16(0xffff),
          u16(method.parameters.length),
        ]),
      );
      for (const [name, parameterType] of method.parameters)
        parameters.push(
          Buffer.concat([
            u32(strings.offset(name)),
            u32(0x08000001 + parameters.length),
            i32(parameterType),
          ]),
        );
    }
    for (const [name, fieldType] of type.fields ?? [])
      fields.push(
        Buffer.concat([
          u32(strings.offset(name)),
          i32(fieldType),
          u32(0x04000001 + fields.length),
        ]),
      );
    for (const index of type.interfaces ?? []) interfaces.push(i32(index));
    types.push(typeRow(strings, type, typeIndex, starts));
  });
  return {
    methods: Buffer.concat(methods),
    parameters: Buffer.concat(parameters),
    fields: Buffer.concat(fields),
    types: Buffer.concat(types),
    interfaces: Buffer.concat(interfaces),
  };
};

const encodeImagesAndAssemblies = (strings: StringPool) => {
  const images = IMAGES.map((image, index) =>
    Buffer.concat([
      u32(strings.offset(image.name)),
      i32(index),
      i32(image.typeStart),
      u32(image.typeCount),
      i32(-1),
      u32(0),
      i32(-1),
      u32(1),
      i32(0),
      u32(index === 1 ? 1 : 0),
    ]),
  );
  const assemblies = IMAGES.map((image, index) =>
    Buffer.concat([
      i32(index),
      u32(0x20000001),
      i32(0),
      i32(index === 1 ? 1 : 0),
      u32(strings.offset(image.assembly)),
      u32(0),
      u32(0),
      u32(0x8004),
      i32(0),
      u32(index === 0 ? 1 : 0),
      ...image.version.map(i32),
      Buffer.from(image.publicKeyToken, "hex"),
    ]),
  );
  return {
    images: Buffer.concat(images),
    assemblies: Buffer.concat(assemblies),
  };
};

/** Header pair order for wire versions 29 through 31. */
const HEADER_SECTIONS = [
  "stringLiterals",
  "stringLiteralData",
  "strings",
  "events",
  "properties",
  "methods",
  "parameterDefaultValues",
  "fieldDefaultValues",
  "fieldAndParameterDefaultValueData",
  "fieldMarshaledSizes",
  "parameters",
  "fields",
  "genericParameters",
  "genericParameterConstraints",
  "genericContainers",
  "nestedTypes",
  "interfaces",
  "vtableMethods",
  "interfaceOffsets",
  "typeDefinitions",
  "images",
  "assemblies",
  "fieldRefs",
  "referencedAssemblies",
  "attributeData",
  "attributeDataRanges",
  "unresolvedIndirectCallParameterTypes",
  "unresolvedIndirectCallParameterRanges",
  "windowsRuntimeTypeNames",
  "windowsRuntimeStrings",
  "exportedTypeDefinitions",
] as const;

/** Build the metadata bytes; every call returns an identical buffer. */
export const createIl2CppMetadata = (): Buffer => {
  const strings = new StringPool();
  const tables = encodeTables(strings);
  const { images, assemblies } = encodeImagesAndAssemblies(strings);
  let literalData = 0;
  const literalTable = Buffer.concat(
    IL2CPP_STRING_LITERALS.map((bytes) => {
      const row = Buffer.concat([u32(bytes.length), u32(literalData)]);
      literalData += bytes.length;
      return row;
    }),
  );
  // One [MonoPInvokeCallback] on Player.OnNativeEvent: count, then the
  // attribute constructor's method index (method 0).
  const attributeData = Buffer.concat([Buffer.from([1]), u32(0)]);
  const attributeRanges = Buffer.concat([
    u32(IL2CPP_FIXTURE.reversePinvokeToken),
    u32(0),
  ]);
  const contents: Record<(typeof HEADER_SECTIONS)[number], Buffer> = {
    ...(Object.fromEntries(
      HEADER_SECTIONS.map((name) => [name, Buffer.alloc(0)]),
    ) as Record<(typeof HEADER_SECTIONS)[number], Buffer>),
    stringLiterals: literalTable,
    stringLiteralData: Buffer.concat(IL2CPP_STRING_LITERALS),
    methods: tables.methods,
    parameters: tables.parameters,
    fields: tables.fields,
    interfaces: tables.interfaces,
    typeDefinitions: tables.types,
    images,
    assemblies,
    referencedAssemblies: i32(0),
    attributeData,
    attributeDataRanges: attributeRanges,
  };
  // Strings last: every other encoder has interned its names by now.
  contents.strings = strings.bytes();
  const header = Buffer.alloc(8 + HEADER_SECTIONS.length * 8);
  header.writeUInt32LE(0xfab11baf, 0);
  header.writeInt32LE(IL2CPP_FIXTURE.wireVersion, 4);
  const body: Buffer[] = [];
  let offset = header.length;
  HEADER_SECTIONS.forEach((name, index) => {
    const bytes = contents[name];
    const padded = Buffer.concat([
      bytes,
      Buffer.alloc((4 - (bytes.length % 4)) % 4),
    ]);
    header.writeUInt32LE(offset, 8 + index * 8);
    header.writeInt32LE(bytes.length, 12 + index * 8);
    body.push(padded);
    offset += padded.length;
  });
  return Buffer.concat([header, ...body]);
};

/** Little-endian section-header and symbol fields relative to `base`. */
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

const TEXT_OFFSET = 0x1000;
const DATA_OFFSET = 0x2000;
const DATA_SIZE = 0x300;
const MODULES = 0x100;
const MODULE_STRUCTS = [0x120, 0x1a0] as const;
const METHOD_POINTERS = 0x220;
const MODULE_NAMES = 0x260;
const LINK_OFFSET = DATA_OFFSET + DATA_SIZE;

/** Native registration tables as IL2CPP emits them for wire version 29. */
const encodeData = (): Buffer => {
  const data = Buffer.alloc(DATA_SIZE);
  const rows = methodRows();
  // Il2CppCodeRegistration: every table empty except codeGenModules at 0x78.
  data.writeUInt32LE(IMAGES.length, 0x78);
  data.writeBigUInt64LE(BigInt(DATA_ADDRESS + MODULES), 0x80);
  let nameOffset = MODULE_NAMES;
  IMAGES.forEach((image, index) => {
    const struct = MODULE_STRUCTS[index] ?? 0;
    data.writeBigUInt64LE(BigInt(DATA_ADDRESS + struct), MODULES + index * 8);
    data.writeBigUInt64LE(BigInt(DATA_ADDRESS + nameOffset), struct);
    nameOffset += data.write(`${image.name}\0`, nameOffset, "latin1");
    const owned = rows.filter(
      ({ typeIndex }) =>
        typeIndex >= image.typeStart &&
        typeIndex < image.typeStart + image.typeCount,
    );
    if (owned.length === 0) return;
    data.writeUInt32LE(owned.length, struct + 8);
    data.writeBigUInt64LE(BigInt(DATA_ADDRESS + METHOD_POINTERS), struct + 16);
    owned.forEach(({ stub }, local) =>
      u64(stub === null ? 0 : IL2CPP_FIXTURE.stub(stub)).copy(
        data,
        METHOD_POINTERS + local * 8,
      ),
    );
  });
  return data;
};

/** Each stub is `mov eax, slot; ret`, padded to 16 bytes with int3. */
const encodeText = (): Buffer => {
  const slots = methodRows().filter(({ stub }) => stub !== null).length;
  const text = Buffer.alloc(slots * STUB_SIZE, 0xcc);
  for (let slot = 0; slot < slots; slot += 1)
    Buffer.concat([Buffer.from([0xb8]), u32(slot), Buffer.from([0xc3])]).copy(
      text,
      slot * STUB_SIZE,
    );
  return text;
};

/**
 * Build the GameAssembly stand-in; every call returns an identical buffer.
 * `symbols: false` keeps the registration tables but drops `g_CodeRegistration`
 * from `.symtab`, as stripped shipping builds do.
 */
export const createIl2CppGameAssembly = ({ symbols = true } = {}): Buffer => {
  const text = encodeText();
  const data = encodeData();
  const symbolNames = Buffer.from(
    symbols ? "\0g_CodeRegistration\0" : "\0",
    "latin1",
  );
  const symtab = Buffer.alloc(symbols ? 48 : 24);
  if (symbols)
    writeFields(symtab, 24, [
      [0, 4, 1],
      [4, 1, 0x11],
      [6, 2, 2],
      [8, 8, IL2CPP_FIXTURE.codeRegistration],
      [16, 8, 0x88],
    ]);
  const sectionNames = Buffer.from(
    "\0.text\0.data\0.symtab\0.strtab\0.shstrtab\0",
    "latin1",
  );
  const symtabOffset = LINK_OFFSET;
  const strtabOffset = symtabOffset + symtab.length;
  const shstrtabOffset = strtabOffset + symbolNames.length;
  const headersOffset =
    Math.ceil((shstrtabOffset + sectionNames.length) / 8) * 8;
  // name offset, type, flags, address, offset, size, link, info, align, entsize
  const sections = [
    [1, 1, 0x6, TEXT_ADDRESS, TEXT_OFFSET, text.length, 0, 0, 16, 0],
    [7, 1, 0x3, DATA_ADDRESS, DATA_OFFSET, DATA_SIZE, 0, 0, 8, 0],
    [13, 2, 0, 0, symtabOffset, symtab.length, 4, 1, 8, 24],
    [21, 3, 0, 0, strtabOffset, symbolNames.length, 0, 0, 1, 0],
    [29, 3, 0, 0, shstrtabOffset, sectionNames.length, 0, 0, 1, 0],
  ] as const;
  const file = Buffer.alloc(headersOffset + (sections.length + 1) * 64);
  file.write("\x7fELF", 0, "latin1");
  // ELFCLASS64, little endian; ET_DYN like a shared GameAssembly.so.
  writeFields(file, 0, [
    [4, 1, 2],
    [5, 1, 1],
    [6, 1, 1],
    [16, 2, 3],
    [18, 2, 62],
    [20, 4, 1],
    [24, 8, TEXT_ADDRESS],
    [32, 8, 64],
    [40, 8, headersOffset],
    [52, 2, 64],
    [54, 2, 56],
    [56, 2, 2],
    [58, 2, 64],
    [60, 2, sections.length + 1],
    [62, 2, sections.length],
  ]);
  const loads = [
    [5, TEXT_OFFSET, TEXT_ADDRESS, text.length],
    [6, DATA_OFFSET, DATA_ADDRESS, DATA_SIZE],
  ] as const;
  loads.forEach(([flags, offset, address, size], index) =>
    writeFields(file, 64 + index * 56, [
      [0, 4, 1],
      [4, 4, flags],
      [8, 8, offset],
      [16, 8, address],
      [24, 8, address],
      [32, 8, size],
      [40, 8, size],
      [48, 8, 0x1000],
    ]),
  );
  text.copy(file, TEXT_OFFSET);
  data.copy(file, DATA_OFFSET);
  symtab.copy(file, symtabOffset);
  symbolNames.copy(file, strtabOffset);
  sectionNames.copy(file, shstrtabOffset);
  sections.forEach(
    (
      [name, type, flags, address, offset, size, link, info, align, entry],
      index,
    ) =>
      writeFields(file, headersOffset + (index + 1) * 64, [
        [0, 4, name],
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
