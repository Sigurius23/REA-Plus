import { ByteCursor, formatFail, unityGuid } from "./UnityBinary.js";
import type { ByteSource } from "./UnityBundle.js";
import { COMMON_STRINGS } from "./UnityStrings.js";

export const MIN_SERIALIZED_VERSION = 9;
export const MAX_SERIALIZED_VERSION = 22;
const MAX_TYPES = 100_000;
const MAX_TREE_NODES = 1_000_000;
const MAX_OBJECTS = 5_000_000;
const MAX_EXTERNALS = 100_000;
/** Metadata (types, object table, externals) read into memory at most. */
export const MAX_METADATA_BYTES = 512 * 1024 * 1024;

/** One type-tree field; `metaFlag & 0x4000` aligns to four bytes after it. */
export interface TypeTreeNode {
  readonly type: string;
  readonly name: string;
  readonly byteSize: number;
  readonly level: number;
  readonly typeFlags: number;
  readonly metaFlag: number;
  readonly children: TypeTreeNode[];
}

export interface SerializedType {
  readonly classId: number;
  readonly stripped: boolean | null;
  scriptTypeIndex: number;
  readonly tree: TypeTreeNode | null;
}

export interface SerializedObject {
  readonly pathId: bigint;
  /** Offset of the object's data from the start of the serialized file. */
  readonly byteStart: number;
  readonly byteSize: number;
  readonly classId: number;
  readonly type: SerializedType | null;
}

export interface SerializedExternal {
  readonly path: string;
  readonly guid: string | null;
  readonly type: number | null;
}

export interface SerializedFile {
  readonly formatVersion: number;
  readonly unityVersion: string;
  readonly targetPlatform: number | null;
  readonly bigEndian: boolean;
  readonly typeTree: boolean;
  readonly types: readonly SerializedType[];
  readonly objects: readonly SerializedObject[];
  readonly scriptReferences: readonly {
    readonly fileIndex: number;
    readonly pathId: bigint;
  }[];
  readonly externals: readonly SerializedExternal[];
  readonly refTypes: number;
  readonly fileSize: number;
  readonly dataOffset: number;
}

interface SerializedHeader {
  readonly version: number;
  readonly fileSize: number;
  readonly dataOffset: number;
  readonly metadataStart: number;
  readonly bigEndian: boolean;
}

const HEADER_BYTES = 48;

/** The fixed header, or null when the bytes are not a supported serialized file. */
export const readSerializedHeader = (
  bytes: Buffer,
  available: number,
): SerializedHeader | null => {
  if (bytes.length < 20) return null;
  const cursor = new ByteCursor(bytes);
  cursor.u32("metadata size");
  let fileSize = cursor.u32("file size");
  const version = cursor.u32("format version");
  let dataOffset = cursor.u32("data offset");
  if (version < MIN_SERIALIZED_VERSION || version > MAX_SERIALIZED_VERSION)
    return null;
  const bigEndian = cursor.u8("endianness") !== 0;
  cursor.skip(3, "reserved");
  if (version >= 22) {
    if (bytes.length < HEADER_BYTES) return null;
    cursor.u32("metadata size");
    fileSize = cursor.offset("file size");
    dataOffset = cursor.offset("data offset");
    cursor.u64("reserved");
  }
  if (
    fileSize > available ||
    fileSize < cursor.position ||
    dataOffset > fileSize ||
    dataOffset < cursor.position
  )
    return null;
  return {
    version,
    fileSize,
    dataOffset,
    metadataStart: cursor.position,
    bigEndian,
  };
};

const COMMON_OFFSETS: ReadonlyMap<number, string> = (() => {
  const offsets = new Map<number, string>();
  let at = 0;
  for (const value of COMMON_STRINGS) {
    offsets.set(at, value);
    at += Buffer.byteLength(value) + 1;
  }
  return offsets;
})();

const commonString = (offset: number): string =>
  COMMON_OFFSETS.get(offset) ?? `common:${String(offset)}`;

/** Blob type trees (format 10 and 12+): a flat node table and a string buffer. */
const readBlobTree = (cursor: ByteCursor, version: number): TypeTreeNode => {
  const count = cursor.count(MAX_TREE_NODES, "type tree node count");
  const stringBytes = cursor.count(64 * 1024 * 1024, "type tree string size");
  if (count === 0) formatFail("Empty type tree.");
  const nodeBytes = version >= 19 ? 32 : 24;
  const table = new ByteCursor(
    cursor.slice(count * nodeBytes, "type tree nodes"),
    0,
    cursor.littleEndian,
  );
  const strings = cursor.slice(stringBytes, "type tree strings");
  const text = (offset: number): string => {
    if ((offset & 0x8000_0000) !== 0) return commonString(offset & 0x7fff_ffff);
    const end = strings.indexOf(0, offset);
    if (offset >= strings.length || end < 0)
      formatFail("Type tree string offset is out of range.");
    return strings.toString("utf8", offset, end);
  };
  const flat = Array.from({ length: count }, () => {
    table.u16("node version");
    const level = table.u8("node level");
    const typeFlags = table.u8("node flags");
    const type = text(table.u32("node type offset"));
    const name = text(table.u32("node name offset"));
    const byteSize = table.i32("node byte size");
    table.i32("node index");
    const metaFlag = table.i32("node meta flags");
    if (version >= 19) table.u64("node reference hash");
    return { type, name, byteSize, level, typeFlags, metaFlag, children: [] };
  });
  return linkTree(flat);
};

/** Rebuild parent links from the depth-first node levels. */
const linkTree = (flat: TypeTreeNode[]): TypeTreeNode => {
  const [root] = flat;
  if (root === undefined || root.level !== 0)
    return formatFail("Type tree does not start at level 0.");
  const stack: TypeTreeNode[] = [root];
  for (const node of flat.slice(1)) {
    while (stack.length > node.level) stack.pop();
    const parent = stack[stack.length - 1];
    if (parent === undefined || stack.length !== node.level)
      formatFail("Type tree levels skip a parent.");
    parent?.children.push(node);
    stack.push(node);
  }
  return root;
};

/** Pre-blob type trees (formats 9 and 11), stored depth-first. */
const readLegacyTree = (cursor: ByteCursor): TypeTreeNode => {
  const flat: TypeTreeNode[] = [];
  const pending: number[] = [1];
  while (pending.length > 0) {
    const last = pending.length - 1;
    if ((pending[last] ?? 0) === 0) {
      pending.pop();
      continue;
    }
    pending[last] = (pending[last] ?? 1) - 1;
    if (flat.length >= MAX_TREE_NODES) formatFail("Type tree is too large.");
    const node: TypeTreeNode = {
      type: cursor.cString("node type", 256),
      name: cursor.cString("node name", 256),
      byteSize: cursor.i32("node byte size"),
      level: last,
      typeFlags: (() => {
        cursor.i32("node index");
        return cursor.i32("node flags");
      })(),
      metaFlag: (() => {
        cursor.i32("node version");
        return cursor.i32("node meta flags");
      })(),
      children: [],
    };
    flat.push(node);
    pending.push(cursor.count(MAX_TREE_NODES, "node child count"));
  }
  return linkTree(flat);
};

const readType = (
  cursor: ByteCursor,
  version: number,
  typeTree: boolean,
  reference: boolean,
): SerializedType => {
  const classId = cursor.i32("class id");
  const stripped = version >= 16 ? cursor.bool("stripped flag") : null;
  const scriptTypeIndex = version >= 17 ? cursor.i16("script type index") : -1;
  if (version >= 13) {
    if (
      (reference && scriptTypeIndex >= 0) ||
      (version < 16 && classId < 0) ||
      (version >= 16 && classId === 114)
    )
      cursor.skip(16, "script id");
    cursor.skip(16, "type hash");
  }
  let tree: TypeTreeNode | null = null;
  if (typeTree) {
    tree =
      version >= 12 || version === 10
        ? readBlobTree(cursor, version)
        : readLegacyTree(cursor);
    if (version >= 21) {
      if (reference) {
        cursor.cString("class name");
        cursor.cString("namespace");
        cursor.cString("assembly name");
      } else {
        const dependencies = cursor.count(MAX_TYPES, "type dependency count");
        cursor.skip(dependencies * 4, "type dependencies");
      }
    }
  }
  return { classId, stripped, scriptTypeIndex, tree };
};

interface ObjectTable {
  readonly header: SerializedHeader;
  readonly bigIds: boolean;
  readonly types: readonly SerializedType[];
}

const readObject = (
  cursor: ByteCursor,
  { header, bigIds, types }: ObjectTable,
): SerializedObject => {
  const { version } = header;
  if (version >= 14) cursor.align(4);
  const pathId =
    bigIds || version >= 14
      ? cursor.i64("path id")
      : BigInt(cursor.i32("path id"));
  const start =
    version >= 22 ? cursor.offset("object start") : cursor.u32("object start");
  const byteSize = cursor.u32("object size");
  const typeId = cursor.i32("object type");
  let type: SerializedType | null;
  let classId: number;
  if (version < 16) {
    classId = cursor.u16("object class id");
    type = types.find((candidate) => candidate.classId === typeId) ?? null;
  } else {
    type =
      types[typeId] ??
      formatFail(`Object type index ${String(typeId)} is out of range.`);
    classId = type.classId;
  }
  if (version < 11) cursor.u16("destroyed flag");
  if (version >= 11 && version < 17) {
    const script = cursor.i16("script type index");
    if (type !== null) type.scriptTypeIndex = script;
  }
  if (version === 15 || version === 16) cursor.u8("stripped flag");
  const byteStart = header.dataOffset + start;
  if (byteStart + byteSize > header.fileSize)
    formatFail(`Object ${pathId.toString()} lies outside the file.`);
  return { pathId, byteStart, byteSize, classId, type };
};

/** Parse a serialized file's metadata: types, object table and externals. */
export const readSerializedFile = (
  source: ByteSource,
  base: number,
  available: number,
): SerializedFile => {
  const head = source.read(base, Math.min(available, HEADER_BYTES));
  const header =
    readSerializedHeader(head, available) ??
    formatFail("Not a supported Unity serialized file (formats 9-22).");
  if (header.dataOffset > MAX_METADATA_BYTES)
    formatFail("Serialized file metadata is too large.");
  const { version } = header;
  const cursor = new ByteCursor(
    source.read(base, header.dataOffset),
    header.metadataStart,
    !header.bigEndian,
  );
  const unityVersion = cursor.cString("Unity version", 64);
  const targetPlatform = cursor.i32("target platform");
  const typeTree = version >= 13 ? cursor.bool("type tree flag") : true;
  const types = Array.from(
    { length: cursor.count(MAX_TYPES, "type count") },
    () => readType(cursor, version, typeTree, false),
  );
  const bigIds =
    version >= 7 && version < 14 ? cursor.i32("big id flag") !== 0 : false;
  const objects = Array.from(
    { length: cursor.count(MAX_OBJECTS, "object count") },
    () => readObject(cursor, { header, bigIds, types }),
  );
  const scriptReferences =
    version >= 11
      ? Array.from(
          { length: cursor.count(MAX_OBJECTS, "script count") },
          () => {
            const fileIndex = cursor.i32("script file index");
            if (version >= 14) cursor.align(4);
            const pathId =
              version >= 14
                ? cursor.i64("script path id")
                : BigInt(cursor.i32("script path id"));
            return { fileIndex, pathId };
          },
        )
      : [];
  const externals = Array.from(
    { length: cursor.count(MAX_EXTERNALS, "external count") },
    () => {
      if (version >= 6) cursor.cString("external temp path");
      const guid =
        version >= 5 ? unityGuid(cursor.slice(16, "external guid")) : null;
      const type = version >= 5 ? cursor.i32("external type") : null;
      return { guid, type, path: cursor.cString("external path", 4096) };
    },
  );
  const refTypes =
    version >= 20
      ? Array.from(
          { length: cursor.count(MAX_TYPES, "reference type count") },
          () => readType(cursor, version, typeTree, true),
        ).length
      : 0;
  return {
    formatVersion: version,
    unityVersion,
    targetPlatform,
    bigEndian: header.bigEndian,
    typeTree,
    types,
    objects,
    scriptReferences,
    externals,
    refTypes,
    fileSize: header.fileSize,
    dataOffset: header.dataOffset,
  };
};
