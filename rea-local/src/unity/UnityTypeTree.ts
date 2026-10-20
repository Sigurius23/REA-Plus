import { ByteCursor, formatFail, MAX_STRING_BYTES } from "./UnityBinary.js";
import type { TypeTreeNode } from "./SerializedFile.js";

/** A field value read through a type tree; byte arrays stay as buffers. */
export type FieldValue =
  | number
  | bigint
  | boolean
  | string
  | Buffer
  | readonly FieldValue[]
  | { readonly [field: string]: FieldValue };

export type FieldMap = ReadonlyMap<string, FieldValue>;

const ALIGN = 0x4000;
const MAX_ELEMENTS = 1_000_000;

const PRIMITIVES: Readonly<Record<string, number>> = {
  bool: 1,
  char: 1,
  SInt8: 1,
  UInt8: 1,
  SInt16: 2,
  UInt16: 2,
  short: 2,
  "unsigned short": 2,
  SInt32: 4,
  UInt32: 4,
  int: 4,
  "unsigned int": 4,
  float: 4,
  "Type*": 4,
  SInt64: 8,
  UInt64: 8,
  "long long": 8,
  "unsigned long long": 8,
  double: 8,
  FileSize: 8,
};

/** Fields REA+ cannot step over without Unity's managed-reference tables. */
const OPAQUE = new Set(["ManagedReferencesRegistry", "ReferencedObject"]);

const isArray = (node: TypeTreeNode | undefined): node is TypeTreeNode =>
  node !== undefined && ((node.typeFlags & 1) !== 0 || node.type === "Array");

const fixedSizes = new WeakMap<TypeTreeNode, number | null>();

/** Bytes a subtree always occupies, or null when it varies or aligns. */
const fixedSize = (node: TypeTreeNode): number | null => {
  const cached = fixedSizes.get(node);
  if (cached !== undefined) return cached;
  let size: number | null;
  if ((node.metaFlag & ALIGN) !== 0 || isArray(node.children[0])) size = null;
  else if (node.children.length === 0)
    size = PRIMITIVES[node.type] ?? (node.byteSize > 0 ? node.byteSize : null);
  else {
    size = 0;
    for (const child of node.children) {
      const part = fixedSize(child);
      if (part === null) {
        size = null;
        break;
      }
      size += part;
    }
  }
  fixedSizes.set(node, size);
  return size;
};

const float = (cursor: ByteCursor, what: string): number => {
  const bytes = cursor.slice(4, what);
  return cursor.littleEndian ? bytes.readFloatLE(0) : bytes.readFloatBE(0);
};

const double = (cursor: ByteCursor, what: string): number => {
  const bytes = cursor.slice(8, what);
  return cursor.littleEndian ? bytes.readDoubleLE(0) : bytes.readDoubleBE(0);
};

const READERS: Readonly<
  Record<string, (cursor: ByteCursor, what: string) => FieldValue>
> = {
  bool: (cursor, what) => cursor.bool(what),
  SInt8: (cursor, what) => (cursor.u8(what) << 24) >> 24,
  char: (cursor, what) => cursor.u8(what),
  UInt8: (cursor, what) => cursor.u8(what),
  SInt16: (cursor, what) => cursor.i16(what),
  short: (cursor, what) => cursor.i16(what),
  UInt16: (cursor, what) => cursor.u16(what),
  "unsigned short": (cursor, what) => cursor.u16(what),
  SInt32: (cursor, what) => cursor.i32(what),
  int: (cursor, what) => cursor.i32(what),
  "Type*": (cursor, what) => cursor.i32(what),
  UInt32: (cursor, what) => cursor.u32(what),
  "unsigned int": (cursor, what) => cursor.u32(what),
  float,
  double,
  SInt64: (cursor, what) => cursor.i64(what),
  "long long": (cursor, what) => cursor.i64(what),
  UInt64: (cursor, what) => cursor.u64(what),
  "unsigned long long": (cursor, what) => cursor.u64(what),
  FileSize: (cursor, what) => cursor.u64(what),
};

const readPrimitive = (cursor: ByteCursor, node: TypeTreeNode): FieldValue => {
  const read = READERS[node.type];
  if (read !== undefined) return read(cursor, node.name);
  if (node.byteSize > 0) return cursor.slice(node.byteSize, node.name);
  return formatFail(`Field ${node.name} has unknown type ${node.type}.`);
};

/** Read (`keep`) or step over one field, honouring its alignment flag. */
const visit = (
  cursor: ByteCursor,
  node: TypeTreeNode,
  keep: boolean,
): FieldValue | undefined => {
  if (OPAQUE.has(node.type))
    formatFail(`Field ${node.name} (${node.type}) cannot be stepped over.`);
  let value: FieldValue | undefined;
  const fixed = keep ? null : fixedSize(node);
  if (fixed !== null) cursor.skip(fixed, node.name);
  else if (node.type === "TypelessData") {
    const length = cursor.count(cursor.remaining, `${node.name} length`);
    const bytes = cursor.slice(length, node.name);
    value = keep ? bytes : undefined;
  } else if (isArray(node.children[0])) value = visitArray(cursor, node, keep);
  else if (node.children.length === 0) {
    const read = readPrimitive(cursor, node);
    value = keep ? read : undefined;
  } else {
    const fields: Record<string, FieldValue> = {};
    for (const child of node.children) {
      const read = visit(cursor, child, keep);
      if (keep && read !== undefined) fields[child.name] = read;
    }
    value = keep ? fields : undefined;
  }
  if ((node.metaFlag & ALIGN) !== 0) cursor.align(4);
  return value;
};

/** `vector`, `map`, `string` and friends: an Array child of size then data. */
const visitArray = (
  cursor: ByteCursor,
  node: TypeTreeNode,
  keep: boolean,
): FieldValue | undefined => {
  const array = node.children[0] as TypeTreeNode;
  const element = array.children[1];
  if (element === undefined)
    return formatFail(`Array ${node.name} has no element type.`);
  const elementSize = fixedSize(element);
  const count = cursor.count(
    elementSize === 0 ? MAX_ELEMENTS : Math.min(MAX_ELEMENTS, cursor.remaining),
    `${node.name} element count`,
  );
  let value: FieldValue | undefined;
  if (elementSize === 1 && (keep || node.type === "string")) {
    if (node.type === "string" && count > MAX_STRING_BYTES)
      formatFail(`String ${node.name} is too long.`);
    const bytes = cursor.slice(count, node.name);
    value = node.type === "string" ? bytes.toString("utf8") : bytes;
  } else if (elementSize !== null && !keep)
    cursor.skip(count * elementSize, node.name);
  else {
    const items: FieldValue[] = [];
    for (let index = 0; index < count; index += 1) {
      const item = visit(cursor, element, keep);
      if (keep && item !== undefined) items.push(item);
    }
    value = keep ? items : undefined;
  }
  if ((array.metaFlag & ALIGN) !== 0) cursor.align(4);
  return keep ? value : undefined;
};

export interface FieldRead {
  readonly fields: FieldMap;
  /** Why reading stopped before every wanted field, if it did. */
  readonly error: string | null;
}

/**
 * Read the wanted top-level fields of one object, stepping over the rest and
 * stopping after the last wanted field the type declares.
 */
export const readTreeFields = (
  tree: TypeTreeNode,
  bytes: Buffer,
  littleEndian: boolean,
  wanted: ReadonlySet<string>,
): FieldRead => {
  const fields = new Map<string, FieldValue>();
  const cursor = new ByteCursor(bytes, 0, littleEndian);
  let last = -1;
  tree.children.forEach((child, index) => {
    if (wanted.has(child.name)) last = index;
  });
  try {
    for (const [index, child] of tree.children.entries()) {
      if (index > last) break;
      const value = visit(cursor, child, wanted.has(child.name));
      if (value !== undefined) fields.set(child.name, value);
    }
    return { fields, error: null };
  } catch (cause: unknown) {
    return {
      fields,
      error: cause instanceof Error ? cause.message : String(cause),
    };
  }
};
