import { ByteCursor, versionAtLeast } from "./UnityBinary.js";
import type { FieldMap, FieldRead, FieldValue } from "./UnityTypeTree.js";

/**
 * Classes whose player-build serialization starts with `m_Name` (Unity's
 * NamedObject subclasses), for files built without type trees.
 */
export const NAMED_CLASS_IDS: ReadonlySet<number> = new Set([
  21, 27, 28, 43, 48, 49, 72, 74, 83, 84, 89, 90, 91, 93, 115, 117, 121, 128,
  134, 142, 150, 152, 156, 187, 188, 200, 206, 213, 221, 238, 240, 241, 243,
  245, 258, 290, 319, 329, 1113, 1120, 850595691, 687078895, 1953259897,
]);

/** Component subclasses, which serialize `m_GameObject` first. */
export const COMPONENT_CLASS_IDS: ReadonlySet<number> = new Set([
  4, 20, 23, 33, 50, 54, 58, 60, 61, 64, 65, 68, 70, 81, 82, 95, 96, 108, 111,
  120, 135, 136, 137, 143, 195, 198, 199, 205, 212, 215, 220, 222, 223, 224,
  225,
]);

export interface LayoutContext {
  readonly littleEndian: boolean;
  readonly formatVersion: number;
  readonly unityVersion: readonly [number, number, number];
}

const pointer = (cursor: ByteCursor, context: LayoutContext): FieldValue => ({
  m_FileID: cursor.i32("file id"),
  m_PathID:
    context.formatVersion >= 14
      ? cursor.i64("path id")
      : BigInt(cursor.i32("path id")),
});

const pointerBytes = (context: LayoutContext) =>
  context.formatVersion >= 14 ? 12 : 8;

const alignedString = (cursor: ByteCursor, what: string): string => {
  const value = cursor.sizedString(what);
  cursor.align(4);
  return value;
};

type Layout = (
  cursor: ByteCursor,
  context: LayoutContext,
  fields: Map<string, FieldValue>,
) => void;

const named: Layout = (cursor, _context, fields) => {
  fields.set("m_Name", alignedString(cursor, "m_Name"));
};

const gameObject: Layout = (cursor, context, fields) => {
  // Before 5.5 each component entry also carried its class ID.
  const entry =
    pointerBytes(context) +
    (versionAtLeast(context.unityVersion, [5, 5, 0]) ? 0 : 4);
  const components = cursor.count(cursor.remaining, "m_Component count");
  cursor.skip(components * entry, "m_Component");
  cursor.u32("m_Layer");
  fields.set("m_Name", alignedString(cursor, "m_Name"));
};

const component: Layout = (cursor, context, fields) => {
  fields.set("m_GameObject", pointer(cursor, context));
};

const monoBehaviour: Layout = (cursor, context, fields) => {
  fields.set("m_GameObject", pointer(cursor, context));
  cursor.u8("m_Enabled");
  cursor.align(4);
  fields.set("m_Script", pointer(cursor, context));
  fields.set("m_Name", alignedString(cursor, "m_Name"));
};

const monoScript: Layout = (cursor, context, fields) => {
  fields.set("m_Name", alignedString(cursor, "m_Name"));
  cursor.i32("m_ExecutionOrder");
  cursor.skip(
    versionAtLeast(context.unityVersion, [5, 0, 0]) ? 16 : 4,
    "m_PropertiesHash",
  );
  fields.set("m_ClassName", alignedString(cursor, "m_ClassName"));
  fields.set("m_Namespace", alignedString(cursor, "m_Namespace"));
  fields.set("m_AssemblyName", alignedString(cursor, "m_AssemblyName"));
};

const assetInfo = (cursor: ByteCursor, context: LayoutContext): FieldValue => ({
  preloadIndex: cursor.i32("preloadIndex"),
  preloadSize: cursor.i32("preloadSize"),
  asset: pointer(cursor, context),
});

const assetBundle: Layout = (cursor, context, fields) => {
  fields.set("m_Name", alignedString(cursor, "m_Name"));
  const preload = cursor.count(cursor.remaining, "m_PreloadTable count");
  cursor.skip(preload * pointerBytes(context), "m_PreloadTable");
  const entries = cursor.count(cursor.remaining, "m_Container count");
  fields.set(
    "m_Container",
    Array.from({ length: entries }, () => ({
      first: alignedString(cursor, "container path"),
      second: assetInfo(cursor, context),
    })),
  );
};

const resourceManager: Layout = (cursor, context, fields) => {
  const entries = cursor.count(cursor.remaining, "m_Container count");
  fields.set(
    "m_Container",
    Array.from({ length: entries }, () => ({
      first: alignedString(cursor, "resource path"),
      second: pointer(cursor, context),
    })),
  );
};

const LAYOUTS: ReadonlyMap<number, Layout> = new Map<number, Layout>([
  [1, gameObject],
  [114, monoBehaviour],
  [115, monoScript],
  [142, assetBundle],
  [147, resourceManager],
]);

/** Whether REA+ knows where this class keeps its name or owner without a type tree. */
export const hasKnownLayout = (classId: number): boolean =>
  LAYOUTS.has(classId) ||
  NAMED_CLASS_IDS.has(classId) ||
  COMPONENT_CLASS_IDS.has(classId);

/** Read the fields REA+ uses from a player-build object without a type tree. */
export const readLayoutFields = (
  classId: number,
  bytes: Buffer,
  context: LayoutContext,
): FieldRead => {
  const layout =
    LAYOUTS.get(classId) ??
    (NAMED_CLASS_IDS.has(classId)
      ? named
      : COMPONENT_CLASS_IDS.has(classId)
        ? component
        : null);
  const fields = new Map<string, FieldValue>();
  if (layout === null) return { fields, error: null };
  try {
    layout(new ByteCursor(bytes, 0, context.littleEndian), context, fields);
    return { fields, error: null };
  } catch (cause: unknown) {
    return {
      fields: fields as FieldMap,
      error: cause instanceof Error ? cause.message : String(cause),
    };
  }
};
