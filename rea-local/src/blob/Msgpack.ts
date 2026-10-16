import {
  BlobFormatError,
  bytesNode,
  node,
  textOf,
  type BlobNode,
} from "./BlobTree.js";

/** MessagePack (msgpack.org spec), one top-level value that must use every byte. */

const MAX_DEPTH = 200;

/** A map key as a path segment: strings as themselves, anything else rendered. */
export const keyText = (key: BlobNode): string =>
  key.type === "string" ? (key.value ?? "") : `${key.type}:${key.value ?? "…"}`;

/** Msgpack's timestamp extension (type -1): 32, 64 or 96 bits. */
const timestamp = (data: Buffer): string | null => {
  let seconds: bigint;
  let nanos = 0;
  if (data.length === 4) seconds = BigInt(data.readUInt32BE(0));
  else if (data.length === 8) {
    const value = data.readBigUInt64BE(0);
    nanos = Number(value >> 34n);
    seconds = value & 0x3ffffffffn;
  } else if (data.length === 12) {
    nanos = data.readUInt32BE(0);
    seconds = data.readBigInt64BE(4);
  } else return null;
  const millis = Number(seconds) * 1000 + Math.floor(nanos / 1e6);
  return Number.isFinite(millis) && Math.abs(millis) < 8.64e15
    ? `${new Date(millis).toISOString()} (+${String(nanos)}ns)`
    : null;
};

const CONSTANTS: Readonly<Record<number, readonly [string, string]>> = {
  0xc0: ["nil", "nil"],
  0xc2: ["bool", "false"],
  0xc3: ["bool", "true"],
};

/** Fixed-size numbers: type, byte count and reader. */
const FIXED: Readonly<
  Record<
    number,
    readonly [string, number, (bytes: Buffer, at: number) => string]
  >
> = {
  0xca: ["float", 4, (b, at) => String(b.readFloatBE(at))],
  0xcb: ["float", 8, (b, at) => String(b.readDoubleBE(at))],
  0xcc: ["int", 1, (b, at) => String(b[at] ?? 0)],
  0xcd: ["int", 2, (b, at) => String(b.readUInt16BE(at))],
  0xce: ["int", 4, (b, at) => String(b.readUInt32BE(at))],
  0xcf: ["int", 8, (b, at) => b.readBigUInt64BE(at).toString()],
  0xd0: ["int", 1, (b, at) => String(b.readInt8(at))],
  0xd1: ["int", 2, (b, at) => String(b.readInt16BE(at))],
  0xd2: ["int", 4, (b, at) => String(b.readInt32BE(at))],
  0xd3: ["int", 8, (b, at) => b.readBigInt64BE(at).toString()],
};

class Reader {
  at = 0;

  constructor(readonly bytes: Buffer) {}

  need(length: number): number {
    if (length < 0 || this.at + length > this.bytes.length)
      throw new BlobFormatError(
        `MessagePack value runs past the end at ${String(this.at)}.`,
      );
    const at = this.at;
    this.at += length;
    return at;
  }

  value(key: BlobNode["key"], depth: number): BlobNode {
    if (depth > MAX_DEPTH)
      throw new BlobFormatError("MessagePack nesting is too deep.");
    const start = this.at;
    const byte = this.bytes[this.need(1)] ?? 0;
    const scalar = (type: string, value: string) =>
      node({ key, type, value, offset: start, length: this.at - start });
    if (byte <= 0x7f) return scalar("int", String(byte));
    if (byte >= 0xe0) return scalar("int", String(byte - 256));
    const constant = CONSTANTS[byte];
    if (constant !== undefined) return scalar(constant[0], constant[1]);
    const fixed = FIXED[byte];
    if (fixed !== undefined) {
      const [type, size, read] = fixed;
      return scalar(type, read(this.bytes, this.need(size)));
    }
    return this.sized(key, byte, start, depth);
  }

  /** Strings, binaries, extensions and containers: a length, then the content. */
  sized(
    key: BlobNode["key"],
    byte: number,
    start: number,
    depth: number,
  ): BlobNode {
    if (byte >= 0x80 && byte <= 0x8f)
      return this.map(key, byte & 0x0f, start, depth);
    if (byte >= 0x90 && byte <= 0x9f)
      return this.array(key, byte & 0x0f, start, depth);
    if (byte >= 0xa0 && byte <= 0xbf) return this.str(key, byte & 0x1f, start);
    if (byte >= 0xc4 && byte <= 0xc6)
      return this.bin(key, this.length(byte - 0xc4), start);
    if (byte >= 0xc7 && byte <= 0xc9)
      return this.ext(key, this.length(byte - 0xc7), start);
    if (byte >= 0xd4 && byte <= 0xd8)
      return this.ext(key, 1 << (byte - 0xd4), start);
    if (byte >= 0xd9 && byte <= 0xdb)
      return this.str(key, this.length(byte - 0xd9), start);
    if (byte === 0xdc || byte === 0xdd)
      return this.array(key, this.length(byte - 0xdc + 1), start, depth);
    if (byte === 0xde || byte === 0xdf)
      return this.map(key, this.length(byte - 0xde + 1), start, depth);
    throw new BlobFormatError(
      `Byte 0x${byte.toString(16)} at ${String(start)} is not a MessagePack type.`,
    );
  }

  bin(key: BlobNode["key"], size: number, start: number): BlobNode {
    const at = this.need(size);
    return node({
      key,
      type: "bytes",
      value: this.bytes.subarray(at, at + size).toString("hex"),
      offset: start,
      length: this.at - start,
    });
  }

  /** A length of 1, 2 or 4 bytes (size class 0, 1, 2). */
  length(sizeClass: number): number {
    const size = 1 << sizeClass;
    const at = this.need(size);
    return size === 1
      ? (this.bytes[at] ?? 0)
      : size === 2
        ? this.bytes.readUInt16BE(at)
        : this.bytes.readUInt32BE(at);
  }

  str(key: BlobNode["key"], size: number, start: number): BlobNode {
    const at = this.need(size);
    const bytes = this.bytes.subarray(at, at + size);
    const text = textOf(bytes);
    // msgpack str should be UTF-8; old "raw" data may not be.
    return text === null
      ? {
          ...bytesNode(key, bytes, start),
          type: "str-bytes",
          length: this.at - start,
        }
      : node({
          key,
          type: "string",
          value: text,
          offset: start,
          length: this.at - start,
        });
  }

  ext(key: BlobNode["key"], size: number, start: number): BlobNode {
    const type = this.bytes.readInt8(this.need(1));
    const at = this.need(size);
    const data = this.bytes.subarray(at, at + size);
    const time = type === -1 ? timestamp(data) : null;
    return node({
      key,
      type: time === null ? `ext ${String(type)}` : "timestamp",
      value: time ?? data.toString("hex"),
      offset: start,
      length: this.at - start,
    });
  }

  array(
    key: BlobNode["key"],
    count: number,
    start: number,
    depth: number,
  ): BlobNode {
    if (count > this.bytes.length - this.at)
      throw new BlobFormatError(
        `A MessagePack array of ${String(count)} cannot fit.`,
      );
    const children = Array.from({ length: count }, (_, index) =>
      this.value(index, depth + 1),
    );
    return node({
      key,
      type: "array",
      offset: start,
      length: this.at - start,
      children,
    });
  }

  map(
    key: BlobNode["key"],
    count: number,
    start: number,
    depth: number,
  ): BlobNode {
    if (count * 2 > this.bytes.length - this.at)
      throw new BlobFormatError(
        `A MessagePack map of ${String(count)} entries cannot fit.`,
      );
    const children: BlobNode[] = [];
    for (let index = 0; index < count; index += 1) {
      const entryKey = this.value(null, depth + 1);
      children.push(this.value(keyText(entryKey), depth + 1));
    }
    return node({
      key,
      type: "map",
      offset: start,
      length: this.at - start,
      children,
    });
  }
}

export const decodeMsgpack = (bytes: Buffer): BlobNode => {
  const reader = new Reader(bytes);
  const root = reader.value(null, 0);
  if (reader.at !== bytes.length)
    throw new BlobFormatError(
      `MessagePack value ends at ${String(reader.at)} of ${String(bytes.length)} bytes.`,
    );
  return root;
};
