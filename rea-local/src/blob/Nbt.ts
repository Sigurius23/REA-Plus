import { BlobFormatError, node, type BlobNode } from "./BlobTree.js";

/**
 * Minecraft NBT: a named root compound. Java Edition writes big-endian
 * values; Bedrock writes little-endian ones, its level.dat behind an 8-byte
 * header (storage version, then length).
 */

const MAX_DEPTH = 512;
const TYPES = [
  "end",
  "byte",
  "short",
  "int",
  "long",
  "float",
  "double",
  "byte_array",
  "string",
  "list",
  "compound",
  "int_array",
  "long_array",
];

/** Java's modified UTF-8: NUL as C0 80 and supplementary characters as surrogate pairs. */
const modifiedUtf8 = (bytes: Buffer): string => {
  let out = "";
  for (let index = 0; index < bytes.length;) {
    const a = bytes[index] ?? 0;
    if (a < 0x80) {
      out += String.fromCharCode(a);
      index += 1;
    } else if ((a & 0xe0) === 0xc0) {
      out += String.fromCharCode(
        ((a & 0x1f) << 6) | ((bytes[index + 1] ?? 0) & 0x3f),
      );
      index += 2;
    } else {
      out += String.fromCharCode(
        ((a & 0x0f) << 12) |
          (((bytes[index + 1] ?? 0) & 0x3f) << 6) |
          ((bytes[index + 2] ?? 0) & 0x3f),
      );
      index += 3;
    }
  }
  return out;
};

class Reader {
  at = 0;

  constructor(
    readonly bytes: Buffer,
    readonly little: boolean,
  ) {}

  need(length: number): number {
    if (length < 0 || this.at + length > this.bytes.length)
      throw new BlobFormatError(
        `NBT value runs past the end at ${String(this.at)}.`,
      );
    const at = this.at;
    this.at += length;
    return at;
  }

  i16(): number {
    const at = this.need(2);
    return this.little
      ? this.bytes.readInt16LE(at)
      : this.bytes.readInt16BE(at);
  }

  i32(): number {
    const at = this.need(4);
    return this.little
      ? this.bytes.readInt32LE(at)
      : this.bytes.readInt32BE(at);
  }

  i64(): bigint {
    const at = this.need(8);
    return this.little
      ? this.bytes.readBigInt64LE(at)
      : this.bytes.readBigInt64BE(at);
  }

  string(): string {
    const head = this.need(2);
    const length = this.little
      ? this.bytes.readUInt16LE(head)
      : this.bytes.readUInt16BE(head);
    const at = this.need(length);
    return modifiedUtf8(this.bytes.subarray(at, at + length));
  }

  count(): number {
    const value = this.i32();
    if (value < 0 || value > this.bytes.length - this.at)
      throw new BlobFormatError(
        `An NBT length of ${String(value)} cannot fit.`,
      );
    return value;
  }

  payload(key: BlobNode["key"], type: number, depth: number): BlobNode {
    if (depth > MAX_DEPTH)
      throw new BlobFormatError("NBT nesting is too deep.");
    const start = this.at;
    const scalar = SCALARS[type];
    if (scalar !== undefined) {
      const value = scalar(this);
      return node({
        key,
        type: TYPES[type] ?? "?",
        value,
        offset: start,
        length: this.at - start,
      });
    }
    if (type === 9) return this.list(key, start, depth);
    if (type === 10) return this.compound(key, start, depth);
    throw new BlobFormatError(`NBT tag type ${String(type)} is not defined.`);
  }

  list(key: BlobNode["key"], start: number, depth: number): BlobNode {
    const itemType = this.bytes[this.need(1)] ?? 0;
    const count = this.count();
    if (count > 0 && (itemType === 0 || itemType >= TYPES.length))
      throw new BlobFormatError(
        `NBT list of unknown type ${String(itemType)}.`,
      );
    const children = Array.from({ length: count }, (_, index) =>
      this.payload(index, itemType, depth + 1),
    );
    return node({
      key,
      type: `list<${TYPES[itemType] ?? "?"}>`,
      offset: start,
      length: this.at - start,
      children,
    });
  }

  compound(key: BlobNode["key"], start: number, depth: number): BlobNode {
    const children: BlobNode[] = [];
    for (;;) {
      const childType = this.bytes[this.need(1)] ?? 0;
      if (childType === 0) break;
      if (childType >= TYPES.length)
        throw new BlobFormatError(
          `NBT tag type ${String(childType)} at ${String(this.at - 1)} is not defined.`,
        );
      const name = this.string();
      children.push(this.payload(name, childType, depth + 1));
    }
    return node({
      key,
      type: "compound",
      offset: start,
      length: this.at - start,
      children,
    });
  }

  f32(): number {
    const at = this.need(4);
    return this.little
      ? this.bytes.readFloatLE(at)
      : this.bytes.readFloatBE(at);
  }

  f64(): number {
    const at = this.need(8);
    return this.little
      ? this.bytes.readDoubleLE(at)
      : this.bytes.readDoubleBE(at);
  }

  byteArray(): string {
    const count = this.count();
    const at = this.need(count);
    return this.bytes.subarray(at, at + count).toString("hex");
  }

  numberArray(wide: boolean): string {
    const count = this.count();
    return `[${Array.from({ length: count }, () => (wide ? this.i64().toString() : String(this.i32()))).join(", ")}]`;
  }
}

/** Readers for the tags that hold one value. */
const SCALARS: Readonly<Record<number, (reader: Reader) => string>> = {
  1: (r) => String(r.bytes.readInt8(r.need(1))),
  2: (r) => String(r.i16()),
  3: (r) => String(r.i32()),
  4: (r) => r.i64().toString(),
  5: (r) => String(r.f32()),
  6: (r) => String(r.f64()),
  7: (r) => r.byteArray(),
  8: (r) => r.string(),
  11: (r) => r.numberArray(false),
  12: (r) => r.numberArray(true),
};

/** Decode NBT; little=true reads Bedrock's byte order. */
export const decodeNbt = (bytes: Buffer, little: boolean): BlobNode => {
  const reader = new Reader(bytes, little);
  if (bytes[0] !== 10)
    throw new BlobFormatError("NBT starts with a compound tag (0x0a).");
  reader.need(1);
  const name = reader.string();
  const root = reader.payload(name, 10, 0);
  if (reader.at !== bytes.length)
    throw new BlobFormatError(
      `NBT ends at ${String(reader.at)} of ${String(bytes.length)} bytes.`,
    );
  return root;
};
