import { BlobFormatError, node, type BlobNode } from "./BlobTree.js";

/** BSON (bsonspec.org 1.1): a length-prefixed document whose length is the whole input. */

const MAX_DEPTH = 100;

/** Where an element's value starts, within which document, and its key. */
interface Site {
  readonly key: BlobNode["key"];
  readonly start: number;
  readonly at: number;
  readonly end: number;
  readonly depth: number;
}

type Leaf = {
  readonly type: string;
  readonly value: string;
  readonly next: number;
};

/** Readers for every element type that holds a single value. */
const LEAVES: Readonly<Record<number, (reader: Reader, site: Site) => Leaf>> = {
  0x01: (r, s) => ({
    type: "double",
    value: String(r.bytes.readDoubleLE(s.at)),
    next: r.fixed(s, 8),
  }),
  0x02: (r, s) => ({ type: "string", ...r.string(s.at, s.end) }),
  0x05: (r, s) => r.binary(s),
  0x06: (_r, s) => ({ type: "undefined", value: "undefined", next: s.at }),
  0x07: (r, s) => ({
    type: "objectid",
    value: r.bytes.subarray(s.at, r.fixed(s, 12)).toString("hex"),
    next: s.at + 12,
  }),
  0x08: (r, s) => ({
    type: "bool",
    value: r.bytes[s.at] === 0 ? "false" : "true",
    next: r.fixed(s, 1),
  }),
  0x09: (r, s) => {
    const next = r.fixed(s, 8);
    const millis = r.bytes.readBigInt64LE(s.at);
    const date = Number(millis);
    return {
      type: "datetime",
      value:
        Math.abs(date) < 8.64e15
          ? new Date(date).toISOString()
          : millis.toString(),
      next,
    };
  },
  0x0a: (_r, s) => ({ type: "null", value: "null", next: s.at }),
  0x0b: (r, s) => {
    const pattern = r.cstring(s.at, s.end);
    const options = r.cstring(pattern.next, s.end);
    return {
      type: "regex",
      value: `/${pattern.text}/${options.text}`,
      next: options.next,
    };
  },
  0x0d: (r, s) => ({ type: "javascript", ...r.string(s.at, s.end) }),
  0x0e: (r, s) => ({ type: "symbol", ...r.string(s.at, s.end) }),
  0x10: (r, s) => ({
    type: "int32",
    value: String(r.bytes.readInt32LE(s.at)),
    next: r.fixed(s, 4),
  }),
  0x11: (r, s) => {
    const next = r.fixed(s, 8);
    return {
      type: "timestamp",
      value: `${String(r.bytes.readUInt32LE(s.at + 4))}:${String(r.bytes.readUInt32LE(s.at))}`,
      next,
    };
  },
  0x12: (r, s) => ({
    type: "int64",
    value: r.bytes.readBigInt64LE(s.at).toString(),
    next: r.fixed(s, 8),
  }),
  0x13: (r, s) => ({
    type: "decimal128",
    value: r.bytes.subarray(s.at, r.fixed(s, 16)).toString("hex"),
    next: s.at + 16,
  }),
  0xff: (_r, s) => ({ type: "minkey", value: "minkey", next: s.at }),
  0x7f: (_r, s) => ({ type: "maxkey", value: "maxkey", next: s.at }),
};

class Reader {
  constructor(readonly bytes: Buffer) {}

  check(at: number, length: number, end: number): void {
    if (length < 0 || at + length > end)
      throw new BlobFormatError(
        `BSON value runs past its document at ${String(at)}.`,
      );
  }

  /** The end of a fixed-size value, checked against its document. */
  fixed(site: Site, size: number): number {
    this.check(site.at, size, site.end);
    return site.at + size;
  }

  cstring(at: number, end: number): { text: string; next: number } {
    const stop = this.bytes.indexOf(0, at);
    if (stop < 0 || stop >= end)
      throw new BlobFormatError(`Unterminated BSON name at ${String(at)}.`);
    return { text: this.bytes.toString("utf8", at, stop), next: stop + 1 };
  }

  /** A BSON string: int32 length including the trailing NUL, then the bytes. */
  string(at: number, end: number): { value: string; next: number } {
    this.check(at, 4, end);
    const length = this.bytes.readInt32LE(at);
    this.check(at + 4, length, end);
    if (length < 1 || this.bytes[at + 4 + length - 1] !== 0)
      throw new BlobFormatError(`Bad BSON string length at ${String(at)}.`);
    return {
      value: this.bytes.toString("utf8", at + 4, at + 4 + length - 1),
      next: at + 4 + length,
    };
  }

  binary(site: Site): Leaf {
    this.check(site.at, 5, site.end);
    const length = this.bytes.readInt32LE(site.at);
    this.check(site.at + 5, length, site.end);
    return {
      type: `binary ${String(this.bytes[site.at + 4] ?? 0)}`,
      value: this.bytes
        .subarray(site.at + 5, site.at + 5 + length)
        .toString("hex"),
      next: site.at + 5 + length,
    };
  }

  document(site: Site, type: "document" | "array"): BlobNode {
    if (site.depth > MAX_DEPTH)
      throw new BlobFormatError("BSON nesting is too deep.");
    const { at } = site;
    this.check(at, 5, site.end);
    const length = this.bytes.readInt32LE(at);
    this.check(at, length, site.end);
    const stop = at + length;
    if (length < 5 || this.bytes[stop - 1] !== 0)
      throw new BlobFormatError(
        `BSON document at ${String(at)} does not end with 0x00.`,
      );
    const children: BlobNode[] = [];
    let cursor = at + 4;
    while (cursor < stop - 1) {
      const elementType = this.bytes[cursor] ?? 0;
      const name = this.cstring(cursor + 1, stop - 1);
      const key = type === "array" ? Number(name.text) : name.text;
      const element = this.element(
        { key, start: cursor, at: name.next, end: stop - 1, depth: site.depth },
        elementType,
      );
      children.push(element.node);
      cursor = element.next;
    }
    if (cursor !== stop - 1)
      throw new BlobFormatError(
        `BSON elements overrun their document at ${String(at)}.`,
      );
    return node({
      key: site.key,
      type,
      offset: site.start,
      length: stop - site.start,
      children,
    });
  }

  element(site: Site, type: number): { node: BlobNode; next: number } {
    if (type === 0x03 || type === 0x04) {
      const child = this.document(
        { ...site, depth: site.depth + 1 },
        type === 0x03 ? "document" : "array",
      );
      return { node: child, next: site.start + child.length };
    }
    const leaf = LEAVES[type];
    if (leaf === undefined)
      throw new BlobFormatError(
        `BSON element type 0x${type.toString(16)} at ${String(site.start)} is not supported.`,
      );
    const { type: kind, value, next } = leaf(this, site);
    return {
      node: node({
        key: site.key,
        type: kind,
        value,
        offset: site.start,
        length: next - site.start,
      }),
      next,
    };
  }
}

export const decodeBson = (bytes: Buffer): BlobNode => {
  if (bytes.length < 5 || bytes.readInt32LE(0) !== bytes.length)
    throw new BlobFormatError(
      "A BSON document's length prefix must equal the input length.",
    );
  return new Reader(bytes).document(
    { key: null, start: 0, at: 0, end: bytes.length, depth: 0 },
    "document",
  );
};
