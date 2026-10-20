import { BlobFormatError, bytesNode, node, type BlobNode } from "./BlobTree.js";

/**
 * Protocol Buffers without a schema, decoded the way protoc --decode_raw
 * does: a length-delimited field is a nested message when it is non-empty
 * and parses completely, otherwise a string or bytes.
 */

const MAX_DEPTH = 100;

class Cursor {
  constructor(
    readonly bytes: Buffer,
    public at: number,
    readonly end: number,
  ) {}

  varint(): bigint | null {
    let value = 0n;
    for (let index = 0; index < 10; index += 1) {
      if (this.at >= this.end) return null;
      const byte = this.bytes[this.at] ?? 0;
      this.at += 1;
      value |= BigInt(byte & 0x7f) << BigInt(7 * index);
      if ((byte & 0x80) === 0) return BigInt.asUintN(64, value);
    }
    return null;
  }
}

const hex = (value: bigint, digits: number) =>
  `0x${value.toString(16).padStart(digits, "0")}`;

const varintNode = (
  field: number,
  value: bigint,
  offset: number,
  length: number,
): BlobNode => {
  const signed = BigInt.asIntN(64, value);
  const zigzag = (value >> 1n) ^ -(value & 1n);
  return node({
    key: field,
    type: "varint",
    value: value.toString(),
    alternatives: {
      ...(signed < 0n ? { int64: signed.toString() } : {}),
      sint64: zigzag.toString(),
      ...(value <= 1n ? { bool: value === 1n ? "true" : "false" } : {}),
    },
    offset,
    length,
  });
};

const fixedNode = (field: number, bytes: Buffer, offset: number): BlobNode => {
  if (bytes.length === 4) {
    const value = bytes.readUInt32LE(0);
    return node({
      key: field,
      type: "fixed32",
      value: String(value),
      alternatives: {
        int32: String(bytes.readInt32LE(0)),
        float: String(bytes.readFloatLE(0)),
        hex: hex(BigInt(value), 8),
      },
      offset,
      length: 4,
    });
  }
  const value = bytes.readBigUInt64LE(0);
  return node({
    key: field,
    type: "fixed64",
    value: value.toString(),
    alternatives: {
      int64: bytes.readBigInt64LE(0).toString(),
      double: String(bytes.readDoubleLE(0)),
      hex: hex(value, 16),
    },
    offset,
    length: 8,
  });
};

const MAX_PACKED = 64;

/** A packed repeated varint field (proto3's default for repeated numbers), when every byte belongs to one. */
const packedVarints = (
  bytes: Buffer,
  start: number,
  end: number,
): string | null => {
  if (end === start) return null;
  const cursor = new Cursor(bytes, start, end);
  const values: string[] = [];
  while (cursor.at < end) {
    const value = cursor.varint();
    if (value === null) return null;
    if (values.length < MAX_PACKED) values.push(value.toString());
  }
  return values.length > 1 || end - start === 1 ? values.join(", ") : null;
};

interface Span {
  readonly bytes: Buffer;
  readonly end: number;
  readonly depth: number;
}

/** What one field contributes: a node, the end of the enclosing group, or a parse failure. */
type Step = BlobNode | { readonly endGroup: number } | null;

/** A length-delimited field: a nested message when it parses completely, otherwise text or bytes. */
const lengthDelimited = (
  span: Span,
  cursor: Cursor,
  field: number,
  fieldStart: number,
): BlobNode | null => {
  const length = cursor.varint();
  if (length === null || length > BigInt(span.end - cursor.at)) return null;
  const from = cursor.at;
  const to = from + Number(length);
  cursor.at = to;
  const nested =
    length > 0n && span.depth < MAX_DEPTH
      ? fields(
          { bytes: span.bytes, end: to, depth: span.depth + 1 },
          from,
          null,
        )
      : null;
  if (nested !== null && nested.end === to)
    return node({
      key: field,
      type: "message",
      offset: fieldStart,
      length: to - fieldStart,
      children: nested.nodes,
    });
  const packed = packedVarints(span.bytes, from, to);
  return {
    ...bytesNode(field, span.bytes.subarray(from, to), fieldStart),
    alternatives: packed === null ? {} : { packed_varints: packed },
    length: to - fieldStart,
  };
};

/** Read one field at the cursor. */
const step = (span: Span, cursor: Cursor): Step => {
  const fieldStart = cursor.at;
  const read = cursor.varint();
  if (read === null) return null;
  // Like protobuf's ReadTag, keep the low 32 bits of an overlong tag varint.
  const tag = read & 0xffffffffn;
  const field = Number(tag >> 3n);
  const wire = Number(tag & 7n);
  if (field === 0) return null;
  if (wire === 0) {
    const value = cursor.varint();
    return value === null
      ? null
      : varintNode(field, value, fieldStart, cursor.at - fieldStart);
  }
  if (wire === 1 || wire === 5) {
    const size = wire === 1 ? 8 : 4;
    if (cursor.at + size > span.end) return null;
    cursor.at += size;
    return fixedNode(
      field,
      span.bytes.subarray(cursor.at - size, cursor.at),
      fieldStart,
    );
  }
  if (wire === 2) return lengthDelimited(span, cursor, field, fieldStart);
  if (wire === 4) return { endGroup: field };
  if (wire !== 3 || span.depth >= MAX_DEPTH) return null;
  const inner = fields({ ...span, depth: span.depth + 1 }, cursor.at, field);
  if (inner === null) return null;
  cursor.at = inner.end;
  return node({
    key: field,
    type: "group",
    offset: fieldStart,
    length: inner.end - fieldStart,
    children: inner.nodes,
  });
};

/** Fields from `start` to the span's end, or to the end-group tag of `group`; null when incomplete. */
const fields = (
  span: Span,
  start: number,
  group: number | null,
): { nodes: BlobNode[]; end: number } | null => {
  const cursor = new Cursor(span.bytes, start, span.end);
  const out: BlobNode[] = [];
  while (cursor.at < span.end) {
    const next = step(span, cursor);
    if (next === null) return null;
    // An end-group tag closes the group it matches and nothing else.
    if ("endGroup" in next)
      return group === next.endGroup ? { nodes: out, end: cursor.at } : null;
    out.push(next);
  }
  return group === null ? { nodes: out, end: cursor.at } : null;
};

/** Decode a whole buffer as one protobuf message. */
export const decodeProtobuf = (bytes: Buffer): BlobNode => {
  const parsed =
    bytes.length === 0
      ? { nodes: [], end: 0 }
      : fields({ bytes, end: bytes.length, depth: 0 }, 0, null);
  if (parsed === null)
    throw new BlobFormatError(
      "Not a complete protobuf message (bad wire type, field 0, or a length past the end).",
    );
  return node({
    key: null,
    type: "message",
    offset: 0,
    length: bytes.length,
    children: parsed.nodes,
  });
};
