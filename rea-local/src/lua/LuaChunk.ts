import {
  decodeLuaString,
  formatNumber,
  type LuaChunk,
  type LuaConstant,
  type LuaDialect,
  type LuaLocal,
  type LuaProto,
  type LuaUpvalue,
} from "./LuaModel.js";
import { LuaFormatError, LuaReader, type LuaSizes } from "./LuaReader.js";

/**
 * PUC Lua 5.1-5.4 binary chunks, read the way each version's lundump.c
 * reads them: the header declares byte order and type sizes, strings carry
 * their length, and functions nest depth first.
 */

const LUAC_TAIL = Buffer.from("\x19\x93\r\n\x1a\n", "latin1");

interface Dialect {
  readonly version: 0x51 | 0x52 | 0x53 | 0x54;
  readonly sizes: LuaSizes;
}

const checkTail = (reader: LuaReader, what: string) => {
  if (!reader.slice(LUAC_TAIL.length).equals(LUAC_TAIL))
    throw new LuaFormatError(
      `The ${what} check bytes are wrong; the chunk is corrupted or was converted as text.`,
    );
};

const readHeader = (
  reader: LuaReader,
): Dialect & { readonly format: number } => {
  reader.at += 4;
  const version = reader.u8();
  const format = reader.u8();
  if (
    version !== 0x51 &&
    version !== 0x52 &&
    version !== 0x53 &&
    version !== 0x54
  )
    throw new LuaFormatError(
      `Lua version byte 0x${version.toString(16)} is not 5.1-5.4.`,
    );
  if (version === 0x51 || version === 0x52) {
    const littleEndian = reader.u8() === 1;
    const [int = 0, sizeT = 0, instruction = 0, number = 0, integral = 0] =
      reader.slice(5);
    if (version === 0x52) checkTail(reader, "LUAC_TAIL");
    return {
      version,
      format,
      sizes: {
        littleEndian,
        int,
        sizeT,
        instruction,
        integer: 0,
        number,
        integralNumber: integral !== 0,
      },
    };
  }
  return readHeader53(reader, version, format);
};

/** 5.3 and 5.4 headers: type sizes, then LUAC_INT and LUAC_NUM to probe byte order and float format. */
const readHeader53 = (
  reader: LuaReader,
  version: 0x53 | 0x54,
  format: number,
): Dialect & { readonly format: number } => {
  checkTail(reader, "LUAC_DATA");
  const declared = Array.from(reader.slice(version === 0x53 ? 5 : 3));
  const [int = 0, sizeT = 0, instruction = 0, integer = 0, number = 0] =
    version === 0x53 ? declared : [0, 0, ...declared];
  // LUAC_INT (0x5678) and LUAC_NUM (370.5) reveal the byte order and float format.
  const probe = reader.slice(integer);
  const littleEndian = probe.readUIntLE(0, Math.min(6, integer)) === 0x5678;
  if (
    !littleEndian &&
    probe.readUIntBE(integer - Math.min(6, integer), Math.min(6, integer)) !==
      0x5678
  )
    throw new LuaFormatError(
      "LUAC_INT is not 0x5678; the integer format is not supported.",
    );
  reader.littleEndian = littleEndian;
  if (reader.float(number) !== 370.5)
    throw new LuaFormatError(
      "LUAC_NUM is not 370.5; the float format is not supported.",
    );
  return {
    version,
    format,
    sizes: {
      littleEndian,
      int,
      sizeT,
      instruction,
      integer,
      number,
      integralNumber: false,
    },
  };
};

/** Per-version primitive readers. */
class Primitives {
  constructor(
    readonly reader: LuaReader,
    readonly dialect: Dialect,
  ) {}

  int(): number {
    if (this.dialect.version === 0x54) return this.reader.varint();
    const value = this.reader.signed(this.dialect.sizes.int);
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new LuaFormatError(
        `Negative or huge count at ${String(this.reader.at)}.`,
      );
    return Number(value);
  }

  string(): Buffer | null {
    const { version, sizes } = this.dialect;
    let size: number;
    if (version === 0x54) size = this.reader.varint();
    else if (version === 0x53) {
      size = this.reader.u8();
      if (size === 0xff) size = this.reader.unsigned(sizes.sizeT);
    } else size = this.reader.unsigned(sizes.sizeT);
    if (size === 0) return null;
    // 5.1/5.2 count the terminating NUL; 5.3/5.4 store size + 1.
    const bytes = this.reader.slice(size - (version <= 0x52 ? 0 : 1));
    return version <= 0x52 ? bytes.subarray(0, bytes.length - 1) : bytes;
  }

  text(): string | null {
    const bytes = this.string();
    return bytes === null ? null : decodeLuaString(bytes).text;
  }

  number(): string {
    const { sizes } = this.dialect;
    if (sizes.integralNumber)
      return this.reader.signed(sizes.number).toString();
    return formatNumber(this.reader.float(sizes.number));
  }

  integer(): string {
    return this.reader.signed(this.dialect.sizes.integer).toString();
  }
}

const constant = (
  index: number,
  type: LuaConstant["type"],
  value: string,
  binary = false,
): LuaConstant => ({
  pool: "k",
  index,
  type,
  value,
  binary,
});

const readConstant = (read: Primitives, index: number): LuaConstant => {
  const { version } = read.dialect;
  const tag = read.reader.u8();
  const asString = () => {
    const bytes = read.string() ?? Buffer.alloc(0);
    const decoded = decodeLuaString(bytes);
    return constant(index, "string", decoded.text, decoded.binary);
  };
  if (tag === 0) return constant(index, "nil", "nil");
  if (version === 0x54) {
    if (tag === 1) return constant(index, "boolean", "false");
    if (tag === 17) return constant(index, "boolean", "true");
    if (tag === 3) return constant(index, "integer", read.integer());
    if (tag === 19) return constant(index, "number", read.number());
    if (tag === 4 || tag === 20) return asString();
  } else {
    if (tag === 1)
      return constant(
        index,
        "boolean",
        read.reader.u8() === 0 ? "false" : "true",
      );
    if (tag === 3) return constant(index, "number", read.number());
    if (version === 0x53 && tag === 19)
      return constant(index, "integer", read.integer());
    if (tag === 4 || (version === 0x53 && tag === 20)) return asString();
  }
  throw new LuaFormatError(
    `Unknown constant type ${String(tag)} at ${String(read.reader.at - 1)}.`,
  );
};

const readCode = (read: Primitives): number[] => {
  const size = read.dialect.sizes.instruction;
  if (size !== 4)
    throw new LuaFormatError(
      `Instructions of ${String(size)} bytes are not supported.`,
    );
  const count = read.reader.count(read.int(), 4);
  return Array.from({ length: count }, () => read.reader.unsigned(4));
};

const vector = <T>(
  read: Primitives,
  item: (index: number) => T,
  unit = 1,
): T[] => {
  const count = read.reader.count(read.int(), unit);
  return Array.from({ length: count }, (_, index) => item(index));
};

/** Lua 5.4 stores line deltas per instruction plus periodic absolute lines. */
const lines54 = (
  deltas: readonly number[],
  absolute: readonly { pc: number; line: number }[],
  lineDefined: number,
): number[] => {
  const out: number[] = [];
  let line = lineDefined;
  let next = 0;
  for (let pc = 0; pc < deltas.length; pc += 1) {
    const mark = absolute[next];
    if (mark !== undefined && mark.pc === pc) {
      line = mark.line;
      next += 1;
    } else line += deltas[pc] ?? 0;
    out.push(line);
  }
  return out;
};

interface Debug {
  readonly source?: string | null;
  readonly lines: (number | null)[];
  readonly locals: LuaLocal[];
  readonly upvalueNames: (string | null)[];
}

/** Locals with the 1-based pcs listings use (luac prints startpc+1 and endpc+1). */
const readLocals = (read: Primitives): LuaLocal[] =>
  vector(read, () => ({
    name: read.text() ?? "",
    startPc: read.int() + 1,
    endPc: read.int() + 1,
  }));

const readDebug = (
  read: Primitives,
  codeLength: number,
  lineDefined: number,
): Debug => {
  const { version } = read.dialect;
  const source = version === 0x52 ? read.text() : undefined;
  if (version === 0x54) {
    const deltas = Array.from(
      read.reader.slice(read.reader.count(read.int())),
      (byte) => (byte > 127 ? byte - 256 : byte),
    );
    const absolute = vector(read, () => ({ pc: read.int(), line: read.int() }));
    const locals = readLocals(read);
    const names = vector(read, () => read.text());
    return {
      lines: deltas.length === 0 ? [] : lines54(deltas, absolute, lineDefined),
      locals,
      upvalueNames: names,
    };
  }
  const lines = vector(read, () => read.int(), 1);
  const locals = readLocals(read);
  const names = vector(read, () => read.text());
  return {
    ...(source === undefined ? {} : { source }),
    lines: lines.length === codeLength ? lines : [],
    locals,
    upvalueNames: names,
  };
};

const readFunction = (
  read: Primitives,
  id: string,
  parent: string | null,
  parentSource: string | null,
): LuaProto => {
  const { version } = read.dialect;
  let source = version === 0x52 ? null : read.text();
  const lineDefined = read.int();
  const lastLineDefined = read.int();
  const nups = version === 0x51 ? read.reader.u8() : 0;
  const params = read.reader.u8();
  const vararg = read.reader.u8() !== 0;
  const maxStack = read.reader.u8();
  const code = readCode(read);
  const constants = vector(read, (index) => readConstant(read, index));
  const children: LuaProto[] = [];
  const childSource = () => source ?? parentSource;
  const readChildren = () =>
    vector(read, (index) => {
      children.push(
        readFunction(read, `${id}/${String(index)}`, id, childSource()),
      );
      return index;
    });
  if (version === 0x51 || version === 0x52) readChildren();
  const upvalueSlots =
    version === 0x51
      ? []
      : vector(read, () => {
          const inStack = read.reader.u8() !== 0;
          const slot = read.reader.u8();
          const kind = version === 0x54 ? read.reader.u8() : null;
          return { inStack, slot, kind };
        });
  if (version >= 0x53) readChildren();
  const debug = readDebug(read, code.length, lineDefined);
  if (debug.source !== undefined) source = debug.source;
  const count =
    version === 0x51
      ? Math.max(nups, debug.upvalueNames.length)
      : upvalueSlots.length;
  const upvalues: LuaUpvalue[] = Array.from({ length: count }, (_, index) => {
    const slot = upvalueSlots[index];
    return {
      index,
      name: debug.upvalueNames[index] ?? null,
      inStack: slot?.inStack ?? null,
      slot: slot?.slot ?? null,
      kind: slot?.kind ?? null,
    };
  });
  return {
    id,
    parent,
    source: source ?? parentSource,
    lineDefined,
    lastLineDefined,
    params,
    vararg,
    maxStack,
    code,
    lines:
      debug.lines.length === code.length ? debug.lines : code.map(() => null),
    constants,
    upvalues,
    locals: debug.locals,
    children,
  };
};

const DIALECTS: Readonly<Record<number, LuaDialect>> = {
  0x51: "lua5.1",
  0x52: "lua5.2",
  0x53: "lua5.3",
  0x54: "lua5.4",
};

/** Read a PUC Lua binary chunk that starts at `start`. */
export const readPucChunk = (bytes: Buffer, start: number): LuaChunk => {
  const reader = new LuaReader(bytes, start);
  const header = readHeader(reader);
  reader.littleEndian = header.sizes.littleEndian;
  const read = new Primitives(reader, header);
  // 5.3 and 5.4 store the main closure's upvalue count before the function.
  if (header.version >= 0x53) reader.u8();
  const main = readFunction(read, "0", null, null);
  const { sizes } = header;
  const stripped =
    main.lines.every((line) => line === null) && main.locals.length === 0;
  return {
    dialect: DIALECTS[header.version] ?? "lua5.1",
    version: header.version,
    format: header.format,
    littleEndian: sizes.littleEndian,
    sizes: {
      ...(sizes.int === 0 ? {} : { int: sizes.int, size_t: sizes.sizeT }),
      instruction: sizes.instruction,
      ...(sizes.integer === 0 ? {} : { lua_Integer: sizes.integer }),
      lua_Number: sizes.number,
    },
    flags: [
      ...(sizes.integralNumber ? ["integral-number"] : []),
      ...(header.format === 0 ? [] : [`format-${String(header.format)}`]),
    ],
    chunkName: main.source,
    stripped,
    main,
    length: reader.at - start,
  };
};
