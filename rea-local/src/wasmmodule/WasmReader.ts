/** WebAssembly bytes that cannot be decoded; reported as an input error. */
export class WasmFormatError extends Error {
  override readonly name = "WasmFormatError";
}

/** A function selection the module does not contain; reported against the function input. */
export class WasmSelectionError extends Error {
  override readonly name = "WasmSelectionError";
}

const VALUE_TYPES: Readonly<Record<number, string>> = {
  0x7f: "i32",
  0x7e: "i64",
  0x7d: "f32",
  0x7c: "f64",
  0x7b: "v128",
  0x78: "i8",
  0x77: "i16",
  0x70: "funcref",
  0x6f: "externref",
  0x6e: "anyref",
  0x6d: "eqref",
  0x6c: "i31ref",
  0x6b: "structref",
  0x6a: "arrayref",
  0x69: "exnref",
  0x71: "nullref",
  0x72: "nullexternref",
  0x73: "nullfuncref",
  0x74: "nullexnref",
};

const HEAP_TYPES: Readonly<Record<number, string>> = {
  0x70: "func",
  0x6f: "extern",
  0x6e: "any",
  0x6d: "eq",
  0x6c: "i31",
  0x6b: "struct",
  0x6a: "array",
  0x69: "exn",
  0x71: "none",
  0x72: "noextern",
  0x73: "nofunc",
  0x74: "noexn",
};

/** A bounded cursor over module bytes with LEB128 and WebAssembly type readers. */
export class WasmReader {
  constructor(
    readonly bytes: Buffer,
    public at: number,
    readonly end: number,
  ) {}

  get done(): boolean {
    return this.at >= this.end;
  }

  private need(length: number): void {
    if (this.at + length > this.end)
      throw new WasmFormatError(
        `Unexpected end of data at ${String(this.at)}.`,
      );
  }

  u8(): number {
    this.need(1);
    const value = this.bytes[this.at] ?? 0;
    this.at += 1;
    return value;
  }

  skip(length: number): void {
    this.need(length);
    this.at += length;
  }

  slice(length: number): Buffer {
    this.need(length);
    const value = this.bytes.subarray(this.at, this.at + length);
    this.at += length;
    return value;
  }

  /** Unsigned LEB128 up to 32 bits. */
  u32(): number {
    let result = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.u8();
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
    }
    throw new WasmFormatError(`LEB128 integer too long at ${String(this.at)}.`);
  }

  /** Unsigned LEB128 up to 64 bits, as a number (memory64 limits). */
  u64(): number {
    let result = 0n;
    let shift = 0n;
    for (let index = 0; index < 10; index += 1) {
      const byte = this.u8();
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return Number(result);
      shift += 7n;
    }
    throw new WasmFormatError(`LEB128 integer too long at ${String(this.at)}.`);
  }

  /** Signed LEB128 of up to `bits` bits. */
  signed(bits: 32 | 33 | 64): bigint {
    let result = 0n;
    let shift = 0n;
    let byte = 0;
    for (let index = 0; index < Math.ceil(bits / 7); index += 1) {
      byte = this.u8();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) {
        if ((byte & 0x40) !== 0) result -= 1n << shift;
        return result;
      }
    }
    throw new WasmFormatError(
      `Signed LEB128 integer too long at ${String(this.at)}.`,
    );
  }

  name(): string {
    const length = this.u32();
    return this.slice(length).toString("utf8");
  }

  /** A heap type: an abstract type byte or a type index (s33). */
  heapType(): string {
    const byte = this.bytes[this.at] ?? 0;
    const abstract = HEAP_TYPES[byte];
    if (abstract !== undefined) {
      this.at += 1;
      return abstract;
    }
    return `$${String(this.signed(33))}`;
  }

  valueType(): string {
    const byte = this.u8();
    if (byte === 0x64 || byte === 0x63)
      return `(ref ${byte === 0x63 ? "null " : ""}${this.heapType()})`;
    const name = VALUE_TYPES[byte];
    if (name === undefined)
      throw new WasmFormatError(
        `Unknown value type 0x${byte.toString(16)} at ${String(this.at - 1)}.`,
      );
    return name;
  }

  vector<T>(read: (reader: this, index: number) => T): T[] {
    const count = this.u32();
    if (count > this.end - this.at)
      throw new WasmFormatError(
        `Vector of ${String(count)} items cannot fit at ${String(this.at)}.`,
      );
    const items: T[] = [];
    for (let index = 0; index < count; index += 1)
      items.push(read(this, index));
    return items;
  }

  /** Limits as memory or table types encode them; memory64 sizes may exceed 32 bits. */
  limits(): {
    minimum: number;
    maximum: number | null;
    shared: boolean;
    memory64: boolean;
  } {
    const flags = this.u8();
    const memory64 = (flags & 0x04) !== 0;
    const read = () => (memory64 ? this.u64() : this.u32());
    const minimum = read();
    const maximum = (flags & 0x01) !== 0 ? read() : null;
    return { minimum, maximum, shared: (flags & 0x02) !== 0, memory64 };
  }

  /** Skip a constant expression up to its end opcode, returning an i32/i64.const value if that is all it is. */
  constant(): number | null {
    const start = this.at;
    const first = this.u8();
    let value: number | null = null;
    if (first === 0x41) value = Number(this.signed(32));
    else if (first === 0x42) value = Number(this.signed(64));
    else this.at = start;
    if (value !== null && this.bytes[this.at] === 0x0b) {
      this.at += 1;
      return value;
    }
    this.at = start;
    // Extended constant expressions: walk instructions until the outer end.
    skipExpression(this);
    return null;
  }
}

/** Walk one expression to its matching end without interpreting it. */
export const skipExpression = (reader: WasmReader): void => {
  let depth = 1;
  while (depth > 0) {
    const opcode = reader.u8();
    if (opcode === 0x0b) depth -= 1;
    else if (opcode === 0x02 || opcode === 0x03 || opcode === 0x04) {
      blockType(reader);
      depth += 1;
    } else skipImmediates(reader, opcode);
  }
};

/** A block type: empty (0x40), a value type, or a type index (s33). */
export const blockType = (reader: WasmReader): void => {
  const byte = reader.bytes[reader.at] ?? 0;
  if (byte === 0x40) reader.at += 1;
  else if (VALUE_TYPES[byte] !== undefined || byte === 0x64 || byte === 0x63)
    reader.valueType();
  else reader.signed(33);
};

const memarg = (reader: WasmReader): void => {
  const align = reader.u32();
  if ((align & 0x40) !== 0) reader.u32();
  reader.u64();
};

/** Immediates of instructions outside the prefixed families. */
const SIMPLE: Readonly<Record<number, (reader: WasmReader) => void>> = {
  0x0c: (r) => r.u32(),
  0x0d: (r) => r.u32(),
  0x0e: (r) => {
    r.vector((reader) => reader.u32());
    r.u32();
  },
  0x10: (r) => r.u32(),
  0x11: (r) => {
    r.u32();
    r.u32();
  },
  0x12: (r) => r.u32(),
  0x13: (r) => {
    r.u32();
    r.u32();
  },
  0x14: (r) => r.u32(),
  0x15: (r) => r.u32(),
  0x07: (r) => r.u32(),
  0x08: (r) => r.u32(),
  0x09: (r) => r.u32(),
  0x18: (r) => r.u32(),
  0x1c: (r) => r.vector((reader) => reader.valueType()),
  0x25: (r) => r.u32(),
  0x26: (r) => r.u32(),
  0x3f: (r) => r.u32(),
  0x40: (r) => r.u32(),
  0x41: (r) => r.signed(32),
  0x42: (r) => r.signed(64),
  0x43: (r) => r.skip(4),
  0x44: (r) => r.skip(8),
  0xd0: (r) => r.heapType(),
  0xd2: (r) => r.u32(),
  0xd5: (r) => r.u32(),
  0xd6: (r) => r.u32(),
};

const NO_IMMEDIATES = new Set([
  0x00, 0x01, 0x05, 0x0a, 0x0b, 0x0f, 0x19, 0x1a, 0x1b, 0xd1, 0xd3, 0xd4,
]);

/** 0xFC: saturating truncation, bulk memory and table instructions. */
const misc = (reader: WasmReader): void => {
  const op = reader.u32();
  if (op <= 7) return;
  const immediates: Readonly<Record<number, number>> = {
    8: 2,
    9: 1,
    10: 2,
    11: 1,
    12: 2,
    13: 1,
    14: 2,
    15: 1,
    16: 1,
    17: 1,
  };
  const count = immediates[op];
  if (count === undefined)
    throw new WasmFormatError(`Unknown 0xFC instruction ${String(op)}.`);
  for (let index = 0; index < count; index += 1) reader.u32();
};

/** 0xFD: SIMD. Loads and stores take a memarg; lane ops take a lane index. */
const simd = (reader: WasmReader): void => {
  const op = reader.u32();
  if (op <= 11 || op === 92 || op === 93) memarg(reader);
  else if (op >= 84 && op <= 91) {
    memarg(reader);
    reader.skip(1);
  } else if (op === 12 || op === 13) reader.skip(16);
  else if (op >= 21 && op <= 34) reader.skip(1);
  else if (op > 0x113)
    throw new WasmFormatError(`Unknown 0xFD instruction ${String(op)}.`);
};

/** 0xFE: atomics. */
const atomic = (reader: WasmReader): void => {
  const op = reader.u32();
  if (op === 0x03) reader.skip(1);
  else if (op <= 0x4e) memarg(reader);
  else throw new WasmFormatError(`Unknown 0xFE instruction ${String(op)}.`);
};

/** 0xFB: GC. Immediates per sub-opcode, from the GC proposal's binary format. */
const gc = (reader: WasmReader): void => {
  const op = reader.u32();
  const types: Readonly<Record<number, readonly ("u32" | "heap" | "flags")[]>> =
    {
      0: ["u32"],
      1: ["u32"],
      2: ["u32", "u32"],
      3: ["u32", "u32"],
      4: ["u32", "u32"],
      5: ["u32", "u32"],
      6: ["u32"],
      7: ["u32"],
      8: ["u32", "u32"],
      9: ["u32", "u32"],
      10: ["u32", "u32"],
      11: ["u32"],
      12: ["u32"],
      13: ["u32"],
      14: ["u32"],
      15: [],
      16: ["u32"],
      17: ["u32", "u32"],
      18: ["u32", "u32"],
      19: ["u32", "u32"],
      20: ["heap"],
      21: ["heap"],
      22: ["heap"],
      23: ["heap"],
      24: ["flags", "u32", "heap", "heap"],
      25: ["flags", "u32", "heap", "heap"],
      26: [],
      27: [],
      28: [],
      29: [],
      30: [],
    };
  const immediates = types[op];
  if (immediates === undefined)
    throw new WasmFormatError(`Unknown 0xFB instruction ${String(op)}.`);
  for (const kind of immediates)
    if (kind === "u32") reader.u32();
    else if (kind === "heap") reader.heapType();
    else reader.skip(1);
};

/** Skip the immediates of one instruction whose opcode has been read. */
export const skipImmediates = (reader: WasmReader, opcode: number): void => {
  if (NO_IMMEDIATES.has(opcode) || (opcode >= 0x45 && opcode <= 0xc4)) return;
  if (opcode >= 0x20 && opcode <= 0x24) {
    reader.u32();
    return;
  }
  if (opcode >= 0x28 && opcode <= 0x3e) {
    memarg(reader);
    return;
  }
  const simple = SIMPLE[opcode];
  if (simple !== undefined) {
    simple(reader);
    return;
  }
  if (opcode === 0x06 || opcode === 0x1f) {
    blockType(reader);
    if (opcode === 0x1f)
      reader.vector((r) => {
        const kind = r.u8();
        if (kind <= 1) r.u32();
        r.u32();
      });
    return;
  }
  if (opcode === 0xfb) gc(reader);
  else if (opcode === 0xfc) misc(reader);
  else if (opcode === 0xfd) simd(reader);
  else if (opcode === 0xfe) atomic(reader);
  else
    throw new WasmFormatError(
      `Unknown opcode 0x${opcode.toString(16)} at ${String(reader.at - 1)}.`,
    );
};
