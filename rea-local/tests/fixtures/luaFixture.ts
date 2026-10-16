/**
 * Lua binary chunks assembled byte by byte in the layouts lundump.c (5.1,
 * 5.3, 5.4) and lj_bcread.c (LuaJIT 2.1) read, including a big-endian
 * build with 4-byte size_t. Opcode numbers come from each version's
 * lopcodes.h / lj_bc.h, not from REA+'s tables.
 */

type Constant =
  | readonly ["nil"]
  | readonly ["bool", boolean]
  | readonly ["num", number]
  | readonly ["int", bigint]
  | readonly ["str", string];

export interface FixtureProto {
  readonly source: string | null;
  readonly line: number;
  readonly lastLine: number;
  readonly params: number;
  readonly vararg: boolean;
  readonly maxStack: number;
  readonly code: readonly number[];
  readonly lines: readonly number[];
  readonly constants: readonly Constant[];
  readonly upvalues: readonly {
    readonly name: string;
    readonly inStack: boolean;
    readonly slot: number;
  }[];
  readonly locals: readonly {
    readonly name: string;
    readonly start: number;
    readonly end: number;
  }[];
  readonly children: readonly FixtureProto[];
}

class Writer {
  readonly parts: Buffer[] = [];

  constructor(readonly littleEndian = true) {}

  bytes(...values: number[]): this {
    this.parts.push(Buffer.from(values));
    return this;
  }

  raw(buffer: Buffer): this {
    this.parts.push(buffer);
    return this;
  }

  int(value: number, size: number): this {
    const buffer = Buffer.alloc(size);
    if (size === 8) {
      if (this.littleEndian) buffer.writeBigUInt64LE(BigInt(value));
      else buffer.writeBigUInt64BE(BigInt(value));
    } else if (this.littleEndian) buffer.writeUIntLE(value, 0, size);
    else buffer.writeUIntBE(value, 0, size);
    return this.raw(buffer);
  }

  double(value: number): this {
    const buffer = Buffer.alloc(8);
    if (this.littleEndian) buffer.writeDoubleLE(value);
    else buffer.writeDoubleBE(value);
    return this.raw(buffer);
  }

  done(): Buffer {
    return Buffer.concat(this.parts);
  }
}

// ---- PUC Lua instruction words ----
/** 5.1-5.3: op:6 A:8 C:9 B:9, Bx:18, sBx biased by 131071. */
export const abc53 = (op: number, a: number, b: number, c: number) =>
  (op | (a << 6) | (c << 14) | (b << 23)) >>> 0;
export const abx53 = (op: number, a: number, bx: number) =>
  (op | (a << 6) | (bx << 14)) >>> 0;
export const asbx53 = (op: number, a: number, sbx: number) =>
  abx53(op, a, sbx + 131071);
/** 5.4: op:7 A:8 k:1 (left 0 here) B:8 C:8, Bx:17 biased by 65535 for sBx, sJ:25 biased by 16777215. */
export const abc54 = (op: number, a: number, b: number, c: number) =>
  (op | (a << 7) | (b << 16) | (c << 24)) >>> 0;
export const abx54 = (op: number, a: number, bx: number) =>
  (op | (a << 7) | (bx << 15)) >>> 0;
export const sj54 = (op: number, sj: number) =>
  (op | ((sj + 16777215) << 7)) >>> 0;
/** LuaJIT: op:8 A:8 D:16, or op:8 A:8 C:8 B:8. */
export const ad = (op: number, a: number, d: number) =>
  (op | (a << 8) | (d << 16)) >>> 0;
export const abcJit = (op: number, a: number, b: number, c: number) =>
  (op | (a << 8) | (c << 16) | (b << 24)) >>> 0;

export const OP51 = {
  LOADK: 1,
  GETGLOBAL: 5,
  SETGLOBAL: 7,
  ADD: 12,
  JMP: 22,
  CALL: 28,
  RETURN: 30,
  CLOSURE: 36,
} as const;
export const OP53 = {
  LOADK: 1,
  GETUPVAL: 5,
  GETTABUP: 6,
  SETTABUP: 8,
  CALL: 36,
  RETURN: 38,
  CLOSURE: 44,
} as const;
export const OP54 = {
  LOADI: 1,
  LOADK: 3,
  GETUPVAL: 9,
  GETTABUP: 11,
  SETFIELD: 18,
  NEWTABLE: 19,
  JMP: 56,
  CALL: 68,
  RETURN: 70,
  RETURN0: 71,
  CLOSURE: 79,
  VARARGPREP: 81,
  EXTRAARG: 82,
} as const;
export const OPJIT = {
  KSTR: 39,
  KSHORT: 41,
  KNUM: 42,
  UGET: 45,
  FNEW: 51,
  GGET: 54,
  GSET: 55,
  CALL: 66,
  RET0: 75,
  JMP: 88,
} as const;

// ---- PUC Lua 5.1 ----
const string51 = (w: Writer, sizeT: number, value: string | null) => {
  if (value === null) return w.int(0, sizeT);
  const bytes = Buffer.from(value, "utf8");
  return w
    .int(bytes.length + 1, sizeT)
    .raw(bytes)
    .bytes(0);
};

const function51 = (
  w: Writer,
  sizes: { int: number; sizeT: number },
  p: FixtureProto,
): void => {
  const int = (value: number) => w.int(value, sizes.int);
  string51(w, sizes.sizeT, p.source);
  int(p.line);
  int(p.lastLine);
  w.bytes(p.upvalues.length, p.params, p.vararg ? 2 : 0, p.maxStack);
  int(p.code.length);
  for (const word of p.code) w.int(word, 4);
  int(p.constants.length);
  for (const k of p.constants) {
    if (k[0] === "nil") w.bytes(0);
    else if (k[0] === "bool") w.bytes(1, k[1] ? 1 : 0);
    else if (k[0] === "num") w.bytes(3).double(k[1]);
    else if (k[0] === "str") string51(w.bytes(4), sizes.sizeT, k[1]);
  }
  int(p.children.length);
  for (const child of p.children) function51(w, sizes, child);
  int(p.lines.length);
  for (const line of p.lines) int(line);
  int(p.locals.length);
  for (const local of p.locals) {
    string51(w, sizes.sizeT, local.name);
    int(local.start);
    int(local.end);
  }
  int(p.upvalues.length);
  for (const upvalue of p.upvalues) string51(w, sizes.sizeT, upvalue.name);
};

export const dump51 = (
  main: FixtureProto,
  options: { littleEndian?: boolean; sizeT?: number } = {},
): Buffer => {
  const littleEndian = options.littleEndian ?? true;
  const sizeT = options.sizeT ?? 8;
  const w = new Writer(littleEndian);
  w.raw(Buffer.from("\x1bLua", "latin1")).bytes(
    0x51,
    0,
    littleEndian ? 1 : 0,
    4,
    sizeT,
    4,
    8,
    0,
  );
  function51(w, { int: 4, sizeT }, main);
  return w.done();
};

// ---- PUC Lua 5.3 ----
const TAIL = Buffer.from("\x19\x93\r\n\x1a\n", "latin1");

const string53 = (w: Writer, value: string | null) => {
  if (value === null) return w.bytes(0);
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length + 1 < 0xff) w.bytes(bytes.length + 1);
  else w.bytes(0xff).int(bytes.length + 1, 8);
  return w.raw(bytes);
};

const function53 = (w: Writer, p: FixtureProto): void => {
  const int = (value: number) => w.int(value, 4);
  string53(w, p.source);
  int(p.line);
  int(p.lastLine);
  w.bytes(p.params, p.vararg ? 1 : 0, p.maxStack);
  int(p.code.length);
  for (const word of p.code) w.int(word, 4);
  int(p.constants.length);
  for (const k of p.constants) {
    if (k[0] === "nil") w.bytes(0);
    else if (k[0] === "bool") w.bytes(1, k[1] ? 1 : 0);
    else if (k[0] === "num") w.bytes(3).double(k[1]);
    else if (k[0] === "int")
      w.bytes(19).raw(Buffer.from(new BigInt64Array([k[1]]).buffer));
    else string53(w.bytes(4), k[1]);
  }
  int(p.upvalues.length);
  for (const upvalue of p.upvalues)
    w.bytes(upvalue.inStack ? 1 : 0, upvalue.slot);
  int(p.children.length);
  for (const child of p.children) function53(w, child);
  int(p.lines.length);
  for (const line of p.lines) int(line);
  int(p.locals.length);
  for (const local of p.locals) {
    string53(w, local.name);
    int(local.start);
    int(local.end);
  }
  int(p.upvalues.length);
  for (const upvalue of p.upvalues) string53(w, upvalue.name);
};

export const dump53 = (main: FixtureProto): Buffer => {
  const w = new Writer();
  w.raw(Buffer.from("\x1bLua", "latin1"))
    .bytes(0x53, 0)
    .raw(TAIL)
    .bytes(4, 8, 4, 8, 8)
    .int(0x5678, 8)
    .double(370.5);
  w.bytes(main.upvalues.length);
  function53(w, main);
  return w.done();
};

// ---- PUC Lua 5.4 ----
/** 5.4 sizes: 7-bit groups, most significant first, the last byte flagged with 0x80. */
const varint = (value: number): number[] => {
  const groups = [value & 0x7f];
  for (
    let rest = Math.floor(value / 128);
    rest > 0;
    rest = Math.floor(rest / 128)
  )
    groups.unshift(rest & 0x7f);
  groups[groups.length - 1] = (groups.at(-1) ?? 0) | 0x80;
  return groups;
};

const string54 = (w: Writer, value: string | null) => {
  if (value === null) return w.bytes(...varint(0));
  const bytes = Buffer.from(value, "utf8");
  return w.bytes(...varint(bytes.length + 1)).raw(bytes);
};

const function54 = (
  w: Writer,
  p: FixtureProto,
  kinds: readonly number[],
): void => {
  const n = (value: number) => w.bytes(...varint(value));
  string54(w, p.source);
  n(p.line);
  n(p.lastLine);
  w.bytes(p.params, p.vararg ? 1 : 0, p.maxStack);
  n(p.code.length);
  for (const word of p.code) w.int(word, 4);
  n(p.constants.length);
  for (const k of p.constants) {
    if (k[0] === "nil") w.bytes(0);
    else if (k[0] === "bool") w.bytes(k[1] ? 17 : 1);
    else if (k[0] === "num") w.bytes(19).double(k[1]);
    else if (k[0] === "int")
      w.bytes(3).raw(Buffer.from(new BigInt64Array([k[1]]).buffer));
    else string54(w.bytes(4), k[1]);
  }
  n(p.upvalues.length);
  p.upvalues.forEach((upvalue, index) =>
    w.bytes(upvalue.inStack ? 1 : 0, upvalue.slot, kinds[index] ?? 0),
  );
  n(p.children.length);
  for (const child of p.children) function54(w, child, []);
  // Relative line deltas, with the first line also given as an absolute entry.
  n(p.lines.length);
  let previous = p.line;
  const deltas = p.lines.map((line) => {
    const delta = line - previous;
    previous = line;
    return delta & 0xff;
  });
  // The first instruction's line is absolute; its delta slot holds ABSLINEINFO (-0x80).
  if (deltas.length > 0) deltas[0] = 0x80;
  w.bytes(...deltas);
  if (p.lines.length > 0) {
    n(1);
    n(0);
    n(p.lines[0] ?? 0);
  } else n(0);
  n(p.locals.length);
  for (const local of p.locals) {
    string54(w, local.name);
    n(local.start);
    n(local.end);
  }
  n(p.lines.length === 0 ? 0 : p.upvalues.length);
  if (p.lines.length > 0)
    for (const upvalue of p.upvalues) string54(w, upvalue.name);
};

export const dump54 = (
  main: FixtureProto,
  kinds: readonly number[] = [],
): Buffer => {
  const w = new Writer();
  w.raw(Buffer.from("\x1bLua", "latin1"))
    .bytes(0x54, 0)
    .raw(TAIL)
    .bytes(4, 8, 8)
    .int(0x5678, 8)
    .double(370.5);
  w.bytes(main.upvalues.length);
  function54(w, main, kinds);
  return w.done();
};

// ---- LuaJIT 2.1 ----
const uleb = (value: number): number[] => {
  const out: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest = Math.floor(rest / 128);
    if (rest > 0) byte |= 0x80;
    out.push(byte);
  } while (rest > 0);
  return out;
};

export interface JitProto {
  readonly flags: number;
  readonly params: number;
  readonly frameSize: number;
  readonly code: readonly number[];
  /** In bytecode index order (D operand d is gc[d]); "child" claims the previous prototype. */
  readonly gc: readonly (readonly ["str", string] | readonly ["child"])[];
  readonly numbers: readonly (
    | readonly ["int", number]
    | readonly ["num", number]
  )[];
  readonly upvalues: readonly { readonly name: string; readonly ref: number }[];
  readonly firstLine: number;
  readonly lines: readonly number[];
  readonly locals: readonly {
    readonly name: string;
    readonly start: number;
    readonly length: number;
  }[];
}

const jitProto = (
  p: JitProto,
  strip: boolean,
  littleEndian: boolean,
): Buffer => {
  const w = new Writer(littleEndian);
  const debug = new Writer(littleEndian);
  if (!strip) {
    for (const line of p.lines) debug.bytes(line - p.firstLine);
    for (const upvalue of p.upvalues)
      debug.raw(Buffer.from(`${upvalue.name}\0`, "utf8"));
    let last = 0;
    for (const local of p.locals) {
      debug
        .raw(Buffer.from(`${local.name}\0`, "utf8"))
        .bytes(...uleb(local.start - last), ...uleb(local.length));
      last = local.start;
    }
    debug.bytes(0);
  }
  const debugBytes = debug.done();
  const numLines = Math.max(0, ...p.lines.map((line) => line - p.firstLine));
  w.bytes(
    p.flags,
    p.params,
    p.frameSize,
    p.upvalues.length,
    ...uleb(p.gc.length),
    ...uleb(p.numbers.length),
    ...uleb(p.code.length),
  );
  if (!strip)
    w.bytes(
      ...uleb(debugBytes.length),
      ...uleb(p.firstLine),
      ...uleb(numLines),
    );
  for (const word of p.code) w.int(word, 4);
  for (const upvalue of p.upvalues) w.int(upvalue.ref, 2);
  // The file holds GC constants in reverse of bytecode index order.
  for (const entry of [...p.gc].reverse()) {
    if (entry[0] === "child") w.bytes(0);
    else {
      const bytes = Buffer.from(entry[1], "utf8");
      w.bytes(...uleb(bytes.length + 5)).raw(bytes);
    }
  }
  for (const entry of p.numbers) {
    if (entry[0] === "int") w.bytes(...uleb(entry[1] * 2));
    else {
      const buffer = Buffer.alloc(8);
      buffer.writeDoubleLE(entry[1]);
      const lo = buffer.readUInt32LE(0);
      const hi = buffer.readUInt32LE(4);
      // ULEB128-33: the low bit of the first byte flags a double.
      const first = uleb(lo * 2 + 1);
      w.bytes(...first, ...uleb(hi));
    }
  }
  w.raw(debugBytes);
  const body = w.done();
  return Buffer.concat([Buffer.from(uleb(body.length)), body]);
};

/** A dump of prototypes in file order (children first, main last). */
export const dumpJit = (
  protos: readonly JitProto[],
  options: { strip?: boolean; littleEndian?: boolean; chunkName?: string } = {},
): Buffer => {
  const strip = options.strip ?? false;
  const littleEndian = options.littleEndian ?? true;
  const flags = (littleEndian ? 0 : 1) | (strip ? 2 : 0) | 8;
  const name = Buffer.from(options.chunkName ?? "@game.lua", "utf8");
  return Buffer.concat([
    Buffer.from([0x1b, 0x4c, 0x4a, 2, ...uleb(flags)]),
    strip
      ? Buffer.alloc(0)
      : Buffer.concat([Buffer.from(uleb(name.length)), name]),
    ...protos.map((proto) => jitProto(proto, strip, littleEndian)),
    Buffer.from([0]),
  ]);
};
