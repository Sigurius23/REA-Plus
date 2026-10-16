import {
  readSerializedFile,
  type SerializedFile,
  type SerializedObject,
} from "./SerializedFile.js";
import { unityVersionParts } from "./UnityBinary.js";
import type { ByteSource } from "./UnityBundle.js";
import {
  hasKnownLayout,
  readLayoutFields,
  type LayoutContext,
} from "./UnityLayouts.js";
import { CLASS_NAMES } from "./UnityTables.js";
import {
  readTreeFields,
  type FieldMap,
  type FieldRead,
  type FieldValue,
} from "./UnityTypeTree.js";

/** Most bytes of one object read to find its fields. */
const MAX_OBJECT_READ = 64 * 1024 * 1024;
/** First read window; most fields REA+ wants sit at the start of an object. */
const FIRST_WINDOW = 64 * 1024;

const WANTED: ReadonlyMap<number, ReadonlySet<string>> = new Map([
  [114, new Set(["m_GameObject", "m_Script", "m_Name"])],
  [115, new Set(["m_Name", "m_ClassName", "m_Namespace", "m_AssemblyName"])],
  [142, new Set(["m_Name", "m_Container", "m_Dependencies"])],
  [147, new Set(["m_Container"])],
]);
const DEFAULT_WANTED: ReadonlySet<string> = new Set(["m_Name", "m_GameObject"]);

export interface ObjectRecord {
  readonly object: SerializedObject;
  readonly className: string | null;
  readonly fields: FieldMap;
  readonly status: "read" | "unread" | "failed";
}

export interface LoadedFile {
  readonly name: string;
  readonly file: SerializedFile | null;
  readonly error: string | null;
  readonly records: readonly ObjectRecord[];
}

export const classNameOf = (object: SerializedObject): string | null =>
  object.type?.tree?.type ?? CLASS_NAMES[object.classId] ?? null;

const readFields = (
  file: SerializedFile,
  object: SerializedObject,
  bytes: Buffer,
): FieldRead | null => {
  const littleEndian = !file.bigEndian;
  const tree = object.type?.tree ?? null;
  if (file.typeTree && tree !== null)
    return readTreeFields(
      tree,
      bytes,
      littleEndian,
      WANTED.get(object.classId) ?? DEFAULT_WANTED,
    );
  if (!hasKnownLayout(object.classId)) return null;
  const context: LayoutContext = {
    littleEndian,
    formatVersion: file.formatVersion,
    unityVersion: unityVersionParts(file.unityVersion),
  };
  return readLayoutFields(object.classId, bytes, context);
};

/** Read an object's fields, widening the window when they lie further in. */
const readObject = (
  source: ByteSource,
  base: number,
  file: SerializedFile,
  object: SerializedObject,
): ObjectRecord => {
  const className = classNameOf(object);
  const limit = Math.min(object.byteSize, MAX_OBJECT_READ);
  let window = Math.min(limit, FIRST_WINDOW);
  for (;;) {
    let read: FieldRead | null;
    try {
      read = readFields(
        file,
        object,
        source.read(base + object.byteStart, window),
      );
    } catch (cause: unknown) {
      read = {
        fields: new Map(),
        error: cause instanceof Error ? cause.message : String(cause),
      };
    }
    if (read === null)
      return { object, className, fields: new Map(), status: "unread" };
    if (read.error === null)
      return { object, className, fields: read.fields, status: "read" };
    // A truncated window fails like corrupt data; only the full read decides.
    if (window >= limit)
      return { object, className, fields: read.fields, status: "failed" };
    window = limit;
  }
};

/** Parse one serialized file and read the fields of every object in it. */
export const loadSerializedFile = (
  name: string,
  source: ByteSource,
  base: number,
  available: number,
): LoadedFile => {
  let file: SerializedFile;
  try {
    file = readSerializedFile(source, base, available);
  } catch (cause: unknown) {
    return {
      name,
      file: null,
      error: cause instanceof Error ? cause.message : String(cause),
      records: [],
    };
  }
  return {
    name,
    file,
    error: null,
    records: file.objects.map((object) =>
      readObject(source, base, file, object),
    ),
  };
};

/** Field helpers over values read through a type tree or a known layout. */
export const textField = (fields: FieldMap, name: string): string | null => {
  const value = fields.get(name);
  return typeof value === "string" ? value : null;
};

export interface Pointer {
  readonly fileId: number;
  readonly pathId: bigint;
}

export const pointerValue = (value: FieldValue | undefined): Pointer | null => {
  if (
    value === undefined ||
    typeof value !== "object" ||
    Buffer.isBuffer(value) ||
    Array.isArray(value)
  )
    return null;
  const record = value as Readonly<Record<string, FieldValue>>;
  const fileId = record["m_FileID"];
  const pathId = record["m_PathID"];
  return typeof fileId === "number" &&
    (typeof pathId === "bigint" || typeof pathId === "number")
    ? { fileId, pathId: BigInt(pathId) }
    : null;
};

export const recordValue = (
  value: FieldValue | undefined,
): Readonly<Record<string, FieldValue>> | null =>
  value !== undefined &&
  typeof value === "object" &&
  !Buffer.isBuffer(value) &&
  !Array.isArray(value)
    ? (value as Readonly<Record<string, FieldValue>>)
    : null;

export const listValue = (
  value: FieldValue | undefined,
): readonly FieldValue[] =>
  Array.isArray(value) ? (value as readonly FieldValue[]) : [];
