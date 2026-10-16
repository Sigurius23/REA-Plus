import {
  decodeLuaString,
  formatNumber,
  type LuaChunk,
  type LuaConstant,
  type LuaLocal,
  type LuaProto,
  type LuaUpvalue,
} from "./LuaModel.js";
import { LuaFormatError, LuaReader } from "./LuaReader.js";

/**
 * LuaJIT bytecode dumps (string.dump, luajit -b), read as lj_bcread.c reads
 * them: prototypes follow one another children first, each child is claimed
 * by a constant of its parent, and debug info is optional.
 */

const F_BE = 0x01;
const F_STRIP = 0x02;
const F_FFI = 0x04;
const F_FR2 = 0x08;
const F_BITOP = 0x10;

const PROTO_VARARG = 0x02;
const UV_LOCAL = 0x8000;
const UV_IMMUTABLE = 0x4000;

/** Internal local names LuaJIT encodes as small numbers in varinfo. */
const VARNAMES = [
  "",
  "(for index)",
  "(for limit)",
  "(for step)",
  "(for generator)",
  "(for state)",
  "(for control)",
];

interface RawProto {
  readonly flags: number;
  readonly params: number;
  readonly frameSize: number;
  readonly code: number[];
  readonly lines: (number | null)[];
  readonly firstLine: number;
  readonly numLines: number;
  /** In bytecode index order: D operand d refers to gc[d]. */
  readonly gc: (Omit<LuaConstant, "index" | "pool"> & { child?: RawProto })[];
  readonly numbers: Omit<LuaConstant, "index" | "pool">[];
  readonly upvalues: LuaUpvalue[];
  readonly locals: LuaLocal[];
}

const tableKey = (reader: LuaReader): string => {
  const type = reader.uleb128();
  if (type >= 5) {
    const text = decodeLuaString(reader.slice(reader.count(type - 5))).text;
    return JSON.stringify(text);
  }
  if (type === 3) return String(reader.uleb128() | 0);
  if (type === 4) {
    const lo = reader.uleb128();
    const hi = reader.uleb128();
    return formatNumber(doubleOf(lo, hi));
  }
  return ["nil", "false", "true"][type] ?? "?";
};

const doubleOf = (lo: number, hi: number): number => {
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32LE(lo >>> 0, 0);
  buffer.writeUInt32LE(hi >>> 0, 4);
  return buffer.readDoubleLE(0);
};

const MAX_TABLE_SHOWN = 16;

/** A template table constant (TDUP), shown as a constructor. */
const readTable = (reader: LuaReader): string => {
  const arrayCount = reader.count(reader.uleb128());
  const hashCount = reader.count(reader.uleb128());
  const parts: string[] = [];
  for (let index = 0; index < arrayCount; index += 1) {
    const value = tableKey(reader);
    if (parts.length < MAX_TABLE_SHOWN)
      parts.push(`[${String(index)}]=${value}`);
  }
  for (let index = 0; index < hashCount; index += 1) {
    const key = tableKey(reader);
    const value = tableKey(reader);
    if (parts.length < MAX_TABLE_SHOWN) parts.push(`[${key}]=${value}`);
  }
  const more = arrayCount + hashCount - parts.length;
  return `{${parts.join(", ")}${more > 0 ? `, …${String(more)} more` : ""}}`;
};

const int64 = (lo: number, hi: number, signed: boolean): string => {
  const value = (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
  return signed ? BigInt.asIntN(64, value).toString() : value.toString();
};

/** ULEB128 of 33 bits whose lowest bit flags a double. */
const uleb33 = (
  reader: LuaReader,
): { readonly value: number; readonly isNumber: boolean } => {
  const first = reader.u8();
  const isNumber = (first & 1) !== 0;
  let value = first >>> 1;
  if (value >= 0x40) {
    value &= 0x3f;
    let shift = 6;
    for (let index = 0; index < 5; index += 1) {
      const byte = reader.u8();
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (byte < 0x80) break;
    }
  }
  return { value: value >>> 0, isNumber };
};

const cString = (reader: LuaReader, end: number): string => {
  const stop = reader.bytes.indexOf(0, reader.at);
  if (stop < 0 || stop >= end)
    throw new LuaFormatError("An unterminated name in LuaJIT debug info.");
  const text = decodeLuaString(reader.bytes.subarray(reader.at, stop)).text;
  reader.at = stop + 1;
  return text;
};

const readDebug = (
  reader: LuaReader,
  end: number,
  sizes: {
    readonly code: number;
    readonly upvalues: number;
    readonly firstLine: number;
    readonly numLines: number;
  },
): { lines: (number | null)[]; names: string[]; locals: LuaLocal[] } => {
  const width = sizes.numLines < 256 ? 1 : sizes.numLines < 65536 ? 2 : 4;
  const lines = Array.from(
    { length: sizes.code },
    () => sizes.firstLine + reader.unsigned(width),
  );
  const names = Array.from({ length: sizes.upvalues }, () =>
    cString(reader, end),
  );
  const locals: LuaLocal[] = [];
  let last = 0;
  while (reader.at < end) {
    const tag = reader.bytes[reader.at] ?? 0;
    let name: string;
    if (tag < VARNAMES.length) {
      reader.at += 1;
      if (tag === 0) break;
      name = VARNAMES[tag] ?? "";
    } else name = cString(reader, end);
    const startPc = last + reader.uleb128();
    last = startPc;
    locals.push({ name, startPc, endPc: startPc + reader.uleb128() });
  }
  return { lines, names, locals };
};

/** GC constants in file order: strings, template tables, children (popped off the stack) and FFI numbers. */
const readGcConstants = (
  reader: LuaReader,
  sizeKgc: number,
  stack: RawProto[],
): RawProto["gc"] => {
  const read: RawProto["gc"] = [];
  for (let index = 0; index < sizeKgc; index += 1) {
    const type = reader.uleb128();
    if (type >= 5) {
      const decoded = decodeLuaString(reader.slice(reader.count(type - 5)));
      read.push({
        type: "string",
        value: decoded.text,
        binary: decoded.binary,
      });
    } else if (type === 1)
      read.push({ type: "table", value: readTable(reader), binary: false });
    else if (type === 0) {
      const child = stack.pop();
      if (child === undefined)
        throw new LuaFormatError(
          "A LuaJIT prototype refers to a child that is not in the dump.",
        );
      read.push({ type: "function", value: "", binary: false, child });
    } else {
      const lo = reader.uleb128();
      const hi = reader.uleb128();
      if (type === 4) {
        const im = doubleOf(reader.uleb128(), reader.uleb128());
        read.push({
          type: "complex",
          value: `${formatNumber(doubleOf(lo, hi))}${im < 0 ? "" : "+"}${formatNumber(im)}i`,
          binary: false,
        });
      } else
        read.push({
          type: type === 2 ? "int64" : "uint64",
          value: `${int64(lo, hi, type === 2)}${type === 2 ? "LL" : "ULL"}`,
          binary: false,
        });
    }
  }
  return read;
};

const readProto = (
  reader: LuaReader,
  stack: RawProto[],
  strip: boolean,
): RawProto => {
  const flags = reader.u8();
  const params = reader.u8();
  const frameSize = reader.u8();
  const sizeUv = reader.u8();
  const sizeKgc = reader.count(reader.uleb128());
  const sizeKn = reader.count(reader.uleb128());
  const sizeBc = reader.count(reader.uleb128(), 4);
  let sizeDbg = 0;
  let firstLine = 0;
  let numLines = 0;
  if (!strip) {
    sizeDbg = reader.uleb128();
    if (sizeDbg > 0) {
      firstLine = reader.uleb128();
      numLines = reader.uleb128();
    }
  }
  const code = Array.from({ length: sizeBc }, () => reader.unsigned(4));
  const uvRefs = Array.from({ length: sizeUv }, () => reader.unsigned(2));
  const read = readGcConstants(reader, sizeKgc, stack);
  const numbers = Array.from({ length: sizeKn }, () => {
    const { value, isNumber } = uleb33(reader);
    if (!isNumber)
      return {
        type: "number" as const,
        value: String(value | 0),
        binary: false,
      };
    return {
      type: "number" as const,
      value: formatNumber(doubleOf(value, reader.uleb128())),
      binary: false,
    };
  });
  const debug =
    sizeDbg > 0
      ? readDebug(reader, reader.at + sizeDbg, {
          code: sizeBc,
          upvalues: sizeUv,
          firstLine,
          numLines,
        })
      : { lines: code.map(() => null), names: [], locals: [] };
  return {
    flags,
    params,
    frameSize,
    code,
    lines: debug.lines,
    firstLine,
    numLines,
    gc: read.reverse(),
    numbers,
    upvalues: uvRefs.map((ref, index) => ({
      index,
      name: debug.names[index] ?? null,
      inStack: (ref & UV_LOCAL) !== 0,
      slot: (ref & UV_LOCAL) !== 0 ? ref & 0xff : ref & 0x3fff,
      kind: (ref & UV_IMMUTABLE) !== 0 ? 1 : 0,
    })),
    locals: debug.locals,
  };
};

/** Give the raw tree the ids, parents and constant pools the shared model uses. */
const finish = (
  raw: RawProto,
  id: string,
  parent: string | null,
  chunkName: string | null,
): LuaProto => {
  const children: LuaProto[] = [];
  const gc: LuaConstant[] = raw.gc.map((entry, index) => {
    if (entry.child === undefined)
      return {
        pool: "gc",
        index,
        type: entry.type,
        value: entry.value,
        binary: entry.binary,
      };
    const childId = `${id}/${String(children.length)}`;
    children.push(finish(entry.child, childId, id, chunkName));
    return {
      pool: "gc",
      index,
      type: "function",
      value: childId,
      binary: false,
    };
  });
  return {
    id,
    parent,
    source: chunkName,
    lineDefined: raw.firstLine,
    lastLineDefined: raw.firstLine + raw.numLines,
    params: raw.params,
    vararg: (raw.flags & PROTO_VARARG) !== 0,
    maxStack: raw.frameSize,
    code: raw.code,
    lines: raw.lines,
    constants: [
      ...gc,
      ...raw.numbers.map((entry, index) => ({
        pool: "num" as const,
        index,
        ...entry,
      })),
    ],
    upvalues: raw.upvalues,
    locals: raw.locals,
    children,
  };
};

/** Read a LuaJIT bytecode dump that starts at `start`. */
export const readLuaJitChunk = (bytes: Buffer, start: number): LuaChunk => {
  const reader = new LuaReader(bytes, start + 3);
  const version = reader.u8();
  if (version !== 1 && version !== 2)
    throw new LuaFormatError(
      `LuaJIT dump version ${String(version)} is not 1 (LuaJIT 2.0) or 2 (2.1).`,
    );
  const flags = reader.uleb128();
  reader.littleEndian = (flags & F_BE) === 0;
  const strip = (flags & F_STRIP) !== 0;
  const chunkName = strip
    ? null
    : decodeLuaString(reader.slice(reader.count(reader.uleb128()))).text;
  const stack: RawProto[] = [];
  for (;;) {
    if (reader.done) break;
    const length = reader.uleb128();
    if (length === 0) break;
    reader.count(length);
    const begin = reader.at;
    stack.push(readProto(reader, stack, strip));
    if (reader.at !== begin + length)
      throw new LuaFormatError(
        `A LuaJIT prototype at ${String(begin)} is ${String(reader.at - begin)} bytes, not the ${String(length)} its length says.`,
      );
  }
  const main = stack.pop();
  if (main === undefined || stack.length > 0)
    throw new LuaFormatError(
      main === undefined
        ? "The LuaJIT dump has no prototypes."
        : "The LuaJIT dump has prototypes no parent claims.",
    );
  return {
    dialect: version === 1 ? "luajit2.0" : "luajit2.1",
    version,
    format: 0,
    littleEndian: reader.littleEndian,
    sizes: {},
    flags: [
      ...((flags & F_BE) !== 0 ? ["big-endian"] : []),
      ...(strip ? ["strip"] : []),
      ...((flags & F_FFI) !== 0 ? ["ffi"] : []),
      ...((flags & F_FR2) !== 0 ? ["fr2"] : []),
      ...((flags & F_BITOP) !== 0 ? ["bitop"] : []),
    ],
    chunkName,
    stripped: strip,
    main: finish(main, "0", null, chunkName),
    length: reader.at - start,
  };
};
