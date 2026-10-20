import { BlobFormatError, node, textOf, type BlobNode } from "./BlobTree.js";
import { keyText } from "./Msgpack.js";

/** CBOR (RFC 8949), one top-level item that must use every byte, indefinite lengths included. */

const MAX_DEPTH = 200;
const BREAK = Symbol("break");

const half = (bits: number): number => {
  const exponent = (bits >> 10) & 0x1f;
  const mantissa = bits & 0x3ff;
  const sign = bits & 0x8000 ? -1 : 1;
  if (exponent === 0) return sign * mantissa * 2 ** -24;
  if (exponent === 31) return mantissa === 0 ? sign * Infinity : Number.NaN;
  return sign * (1 + mantissa / 1024) * 2 ** (exponent - 15);
};

class Reader {
  at = 0;

  constructor(readonly bytes: Buffer) {}

  need(length: number): number {
    if (length < 0 || this.at + length > this.bytes.length)
      throw new BlobFormatError(
        `CBOR item runs past the end at ${String(this.at)}.`,
      );
    const at = this.at;
    this.at += length;
    return at;
  }

  /** The argument of a head: immediate, or 1/2/4/8 following bytes; null for indefinite. */
  argument(info: number): bigint | null {
    if (info < 24) return BigInt(info);
    if (info === 31) return null;
    if (info > 27)
      throw new BlobFormatError(
        `Reserved CBOR additional info ${String(info)} at ${String(this.at - 1)}.`,
      );
    const size = 1 << (info - 24);
    const at = this.need(size);
    if (size === 1) return BigInt(this.bytes[at] ?? 0);
    if (size === 2) return BigInt(this.bytes.readUInt16BE(at));
    if (size === 4) return BigInt(this.bytes.readUInt32BE(at));
    return this.bytes.readBigUInt64BE(at);
  }

  count(value: bigint): number {
    if (value > BigInt(this.bytes.length - this.at))
      throw new BlobFormatError(
        `A CBOR length of ${value.toString()} cannot fit.`,
      );
    return Number(value);
  }

  item(key: BlobNode["key"], depth: number): BlobNode | typeof BREAK {
    if (depth > MAX_DEPTH)
      throw new BlobFormatError("CBOR nesting is too deep.");
    const start = this.at;
    const head = this.bytes[this.need(1)] ?? 0;
    const major = head >> 5;
    if (major === 7) return this.simple(key, head & 0x1f, start);
    const argument = this.argument(head & 0x1f);
    const make = (
      type: string,
      value: string | null,
      children: BlobNode[] = [],
    ) =>
      node({
        key,
        type,
        value,
        offset: start,
        length: this.at - start,
        children,
      });
    if (major <= 1) {
      if (argument === null)
        throw new BlobFormatError("Indefinite length on a CBOR integer.");
      return make("int", (major === 0 ? argument : -1n - argument).toString());
    }
    if (major <= 3) {
      const bytes =
        argument === null
          ? this.chunks(major)
          : this.bytes.subarray(this.need(this.count(argument)), this.at);
      const text = major === 3 ? textOf(bytes) : null;
      return text === null
        ? make(major === 2 ? "bytes" : "str-bytes", bytes.toString("hex"))
        : make("string", text);
    }
    if (major === 4)
      return make(
        "array",
        null,
        this.items(argument, depth, (index) => this.item(index, depth + 1)),
      );
    if (major === 5)
      return make(
        "map",
        null,
        this.items(argument, depth, () => this.entry(depth)),
      );
    if (argument === null)
      throw new BlobFormatError("Indefinite length on a CBOR tag.");
    const content = this.item("value", depth + 1);
    if (content === BREAK)
      throw new BlobFormatError("A CBOR tag without content.");
    return make(`tag ${argument.toString()}`, null, [content]);
  }

  /** A definite number of items, or items up to a break when the length is indefinite. */
  items(
    argument: bigint | null,
    _depth: number,
    read: (index: number) => BlobNode | typeof BREAK,
  ): BlobNode[] {
    const children: BlobNode[] = [];
    const total = argument === null ? Infinity : this.count(argument);
    for (let index = 0; index < total; index += 1) {
      const child = read(index);
      if (child === BREAK) {
        if (argument !== null)
          throw new BlobFormatError(
            "A break inside a definite-length CBOR container.",
          );
        break;
      }
      children.push(child);
    }
    return children;
  }

  /** One map entry: the value node keyed by its rendered key. */
  entry(depth: number): BlobNode | typeof BREAK {
    const entryKey = this.item(null, depth + 1);
    if (entryKey === BREAK) return BREAK;
    const value = this.item(keyText(entryKey), depth + 1);
    if (value === BREAK)
      throw new BlobFormatError("A CBOR map key without a value.");
    return value;
  }

  /** Concatenated chunks of an indefinite byte or text string. */
  chunks(major: number): Buffer {
    const parts: Buffer[] = [];
    for (;;) {
      const head = this.bytes[this.need(1)] ?? 0;
      if (head === 0xff) return Buffer.concat(parts);
      if (head >> 5 !== major)
        throw new BlobFormatError(
          "A chunk of the wrong type inside an indefinite CBOR string.",
        );
      const size = this.argument(head & 0x1f);
      if (size === null)
        throw new BlobFormatError("Nested indefinite CBOR string.");
      const at = this.need(this.count(size));
      parts.push(this.bytes.subarray(at, at + Number(size)));
    }
  }

  simple(
    key: BlobNode["key"],
    info: number,
    start: number,
  ): BlobNode | typeof BREAK {
    const make = (type: string, value: string) =>
      node({ key, type, value, offset: start, length: this.at - start });
    if (info === 31) return BREAK;
    if (info === 20) return make("bool", "false");
    if (info === 21) return make("bool", "true");
    if (info === 22) return make("null", "null");
    if (info === 23) return make("undefined", "undefined");
    if (info === 25)
      return make("float", String(half(this.bytes.readUInt16BE(this.need(2)))));
    if (info === 26)
      return make("float", String(this.bytes.readFloatBE(this.need(4))));
    if (info === 27)
      return make("float", String(this.bytes.readDoubleBE(this.need(8))));
    if (info === 24)
      return make("simple", String(this.bytes[this.need(1)] ?? 0));
    if (info < 24) return make("simple", String(info));
    throw new BlobFormatError(
      `Reserved CBOR simple value ${String(info)} at ${String(start)}.`,
    );
  }
}

export const decodeCbor = (bytes: Buffer): BlobNode => {
  const reader = new Reader(bytes);
  const root = reader.item(null, 0);
  if (root === BREAK) throw new BlobFormatError("CBOR starts with a break.");
  if (reader.at !== bytes.length)
    throw new BlobFormatError(
      `CBOR item ends at ${String(reader.at)} of ${String(bytes.length)} bytes.`,
    );
  return root;
};
