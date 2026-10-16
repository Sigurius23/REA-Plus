/** A file or entry that is not a readable Godot resource, script or save. */
export class GodotFormatError extends Error {}

/** A selection (entry, resource, node, view, key) that does not fit the file. */
export class GodotSelectionError extends Error {
  constructor(
    message: string,
    readonly field:
      | "entry"
      | "resource"
      | "node"
      | "view"
      | "key_env"
      | "password_env"
      | "engine",
  ) {
    super(message);
  }
}

/** Little- or big-endian reads that refuse to run past the end. */
export class Reader {
  constructor(
    readonly bytes: Buffer,
    public at = 0,
    public big = false,
  ) {}

  need(length: number, what = "value"): number {
    if (length < 0 || this.at + length > this.bytes.length)
      throw new GodotFormatError(
        `The ${what} at ${String(this.at)} runs past the end of ${String(this.bytes.length)} bytes.`,
      );
    const at = this.at;
    this.at += length;
    return at;
  }

  u8(): number {
    return this.bytes[this.need(1)] ?? 0;
  }

  u16(): number {
    const at = this.need(2);
    return this.big ? this.bytes.readUInt16BE(at) : this.bytes.readUInt16LE(at);
  }

  u32(): number {
    const at = this.need(4);
    return this.big ? this.bytes.readUInt32BE(at) : this.bytes.readUInt32LE(at);
  }

  i32(): number {
    const at = this.need(4);
    return this.big ? this.bytes.readInt32BE(at) : this.bytes.readInt32LE(at);
  }

  u64(): bigint {
    const at = this.need(8);
    return this.big
      ? this.bytes.readBigUInt64BE(at)
      : this.bytes.readBigUInt64LE(at);
  }

  i64(): bigint {
    const at = this.need(8);
    return this.big
      ? this.bytes.readBigInt64BE(at)
      : this.bytes.readBigInt64LE(at);
  }

  f32(): number {
    const at = this.need(4);
    return this.big ? this.bytes.readFloatBE(at) : this.bytes.readFloatLE(at);
  }

  f64(): number {
    const at = this.need(8);
    return this.big ? this.bytes.readDoubleBE(at) : this.bytes.readDoubleLE(at);
  }

  take(length: number, what = "data"): Buffer {
    const at = this.need(length, what);
    return this.bytes.subarray(at, at + length);
  }

  /** A u32 length then UTF-8; Godot counts and stores a trailing NUL. */
  text(length = this.u32()): string {
    return utf8(this.take(length, "string"));
  }
}

/** UTF-8 without the NUL terminators Godot stores. */
export const utf8 = (bytes: Buffer): string =>
  bytes.toString("utf8").replace(/\0+$/u, "");

/** Shortest decimal that reads back as the same single-precision float. */
const single = (value: number): string => {
  for (let digits = 1; digits <= 9; digits += 1) {
    const text = value.toPrecision(digits);
    if (Math.fround(Number(text)) === value) return String(Number(text));
  }
  return String(value);
};

/** A float as GDScript or a text resource writes it: inf, nan, or decimal. */
export const realText = (value: number, isSingle: boolean): string => {
  if (Number.isNaN(value)) return "nan";
  if (!Number.isFinite(value)) return value > 0 ? "inf" : "-inf";
  return isSingle ? single(value) : String(value);
};

/** A standalone float keeps a decimal point, as Godot prints it. */
export const floatText = (value: number, isSingle: boolean): string => {
  const text = realText(value, isSingle);
  return /^-?\d+$/u.test(text) ? `${text}.0` : text;
};

const UID_ALPHABET = "abcdefghijklmnopqrstuvwxy012345678";

/** A ResourceUID as Godot prints it (uid://...); -1 means none. */
export const uidText = (id: bigint): string | null => {
  if (id < 0n || id === BigInt.asUintN(64, -1n)) return null;
  let rest = id;
  let text = "";
  do {
    text = `${UID_ALPHABET[Number(rest % 34n)] ?? "?"}${text}`;
    rest /= 34n;
  } while (rest > 0n);
  return `uid://${text}`;
};

const ESCAPES: Readonly<Record<string, string>> = {
  "\\": "\\\\",
  '"': '\\"',
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

/** A string literal as GDScript and text resources write it. */
export const quoted = (text: string): string =>
  `"${[...text]
    .map((char) => {
      const code = char.codePointAt(0) ?? 0;
      return (
        ESCAPES[char] ??
        (code < 0x20 ? `\\u${code.toString(16).padStart(4, "0")}` : char)
      );
    })
    .join("")}"`;
