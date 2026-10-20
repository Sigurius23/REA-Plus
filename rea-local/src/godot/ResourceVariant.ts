import { GodotFormatError, type Reader } from "./GodotBytes.js";
import { engineNames, NIL, type GodotValue } from "./GodotValues.js";

/**
 * Variants as binary resources (.res, .scn) store them: Godot's
 * resource_format_binary.cpp numbering, the same in Godot 3 and 4 apart from
 * types Godot 4 added.
 */

export interface ResourceContext {
  readonly reader: Reader;
  readonly major: number;
  /** Binary resource format version; NodePaths changed at 3. */
  readonly format: number;
  readonly real64: boolean;
  readonly strings: readonly string[];
  readonly external: readonly { readonly path: string }[];
  /** Godot 4 refers to sub-resources by position; Godot 3 by their numeric id. */
  readonly internalIds: readonly string[] | null;
}

const MAX_DEPTH = 512;

type Element = "real" | "float" | "int";

const math = (
  major: number,
): Readonly<Record<number, readonly [string, number, Element]>> => {
  const names = engineNames(major);
  return {
    10: ["Vector2", 2, "real"],
    11: ["Rect2", 4, "real"],
    12: ["Vector3", 3, "real"],
    13: ["Plane", 4, "real"],
    14: [names.quaternion, 4, "real"],
    15: ["AABB", 6, "real"],
    16: ["Basis", 9, "real"],
    17: [names.transform3d, 12, "real"],
    18: ["Transform2D", 6, "real"],
    20: ["Color", 4, "float"],
    45: ["Vector2i", 2, "int"],
    46: ["Rect2i", 4, "int"],
    47: ["Vector3i", 3, "int"],
    50: ["Vector4", 4, "real"],
    51: ["Vector4i", 4, "int"],
    52: ["Projection", 16, "real"],
  };
};

/** Packed arrays: name, components per element, and element kind. */
const packed = (
  major: number,
): Readonly<
  Record<
    number,
    readonly [string, number, Element | "byte" | "int64" | "double"]
  >
> => {
  const names = engineNames(major);
  return {
    31: [names.bytes, 1, "byte"],
    32: [names.int32, 1, "int"],
    33: [names.float32, 1, "float"],
    35: [names.vector3s, 3, "real"],
    36: [names.colors, 4, "float"],
    37: [names.vector2s, 2, "real"],
    48: ["PackedInt64Array", 1, "int64"],
    49: ["PackedFloat64Array", 1, "double"],
    53: ["PackedVector4Array", 4, "real"],
  };
};

/** A string-table reference, or an inline string when the high bit is set. */
export const tableString = (context: ResourceContext): string => {
  const id = context.reader.u32();
  if ((id & 0x80000000) !== 0) return context.reader.text(id & 0x7fffffff);
  const text = context.strings[id];
  if (text === undefined)
    throw new GodotFormatError(
      `String ${String(id)} is not in the table of ${String(context.strings.length)}.`,
    );
  return text;
};

const element = (context: ResourceContext, kind: Element): number => {
  const { reader } = context;
  if (kind === "int") return reader.i32();
  if (kind === "float") return reader.f32();
  return context.real64 ? reader.f64() : reader.f32();
};

const packedArray = (
  context: ResourceContext,
  [type, width, kind]: readonly [string, number, string],
): GodotValue => {
  const { reader } = context;
  const count = reader.u32() * width;
  if (count * (kind === "byte" ? 1 : 4) > reader.bytes.length - reader.at)
    throw new GodotFormatError(
      `A ${type} of ${String(count)} values cannot fit.`,
    );
  let items: (number | bigint)[];
  if (kind === "byte") {
    items = [...reader.take(count)];
    reader.need((4 - (count % 4)) % 4, "padding");
  } else if (kind === "int64")
    items = Array.from({ length: count }, () => reader.i64());
  else if (kind === "double")
    items = Array.from({ length: count }, () => reader.f64());
  else
    items = Array.from({ length: count }, () =>
      element(context, kind as Element),
    );
  return {
    kind: "packed",
    type,
    items,
    width,
    single: kind === "float" || (kind === "real" && !context.real64),
  };
};

const nodePath = (context: ResourceContext): GodotValue => {
  const { reader } = context;
  const names = reader.u16();
  const packedCount = reader.u16();
  const absolute = (packedCount & 0x8000) !== 0;
  // Before format 3 the property name was stored as one more subname.
  const subnames = (packedCount & 0x7fff) + (context.format < 3 ? 1 : 0);
  const parts = Array.from({ length: names }, () => tableString(context));
  const sub = Array.from({ length: subnames }, () => tableString(context));
  return {
    kind: "node_path",
    value: `${absolute ? "/" : ""}${parts.join("/")}${sub.map((name) => `:${name}`).join("")}`,
  };
};

const object = (context: ResourceContext): GodotValue => {
  const { reader } = context;
  const kind = reader.u32();
  const ref = (
    reference: "external" | "internal",
    target: string,
  ): GodotValue => ({ kind: "object", reference, target, properties: [] });
  if (kind === 0)
    return { kind: "object", reference: "null", target: "", properties: [] };
  if (kind === 1) {
    reader.text(); // the type, kept by the path's own resource
    return ref("external", reader.text());
  }
  const index = reader.u32();
  if (kind === 2)
    return ref(
      "internal",
      context.internalIds === null
        ? String(index)
        : (context.internalIds[index] ?? `#${String(index)}`),
    );
  if (kind === 3)
    return ref(
      "external",
      context.external[index]?.path ?? `#${String(index)}`,
    );
  throw new GodotFormatError(
    `Object reference kind ${String(kind)} is unknown.`,
  );
};

const container = (
  context: ResourceContext,
  type: number,
  depth: number,
): GodotValue => {
  const count = context.reader.u32() & 0x7fffffff;
  if (count > context.reader.bytes.length - context.reader.at)
    throw new GodotFormatError(`A container of ${String(count)} cannot fit.`);
  if (type === 30)
    return {
      kind: "array",
      typed: null,
      items: Array.from({ length: count }, () =>
        resourceVariant(context, depth + 1),
      ),
    };
  return {
    kind: "dictionary",
    typed: null,
    entries: Array.from(
      { length: count },
      () =>
        [
          resourceVariant(context, depth + 1),
          resourceVariant(context, depth + 1),
        ] as const,
    ),
  };
};

const scalar = (
  context: ResourceContext,
  type: number,
): GodotValue | undefined => {
  const { reader } = context;
  switch (type) {
    case 1:
      return NIL;
    case 2:
      return { kind: "bool", value: reader.u32() !== 0 };
    case 3:
      return { kind: "int", value: BigInt(reader.i32()) };
    case 40:
      return { kind: "int", value: reader.i64() };
    case 4:
      return {
        kind: "float",
        value: context.real64 ? reader.f64() : reader.f32(),
        single: !context.real64,
      };
    case 41:
      return { kind: "float", value: reader.f64(), single: false };
    case 5:
      return { kind: "string", value: reader.text() };
    case 44:
      return { kind: "string_name", value: reader.text() };
    case 22:
      return nodePath(context);
    case 23:
      return { kind: "opaque", type: "RID", value: String(reader.u32()) };
    case 24:
      return object(context);
    case 42:
      return { kind: "opaque", type: "Callable", value: "" };
    case 43:
      return { kind: "opaque", type: "Signal", value: "" };
    default:
      return undefined;
  }
};

/** One Variant at the reader's position. */
export const resourceVariant = (
  context: ResourceContext,
  depth = 0,
): GodotValue => {
  if (depth > MAX_DEPTH)
    throw new GodotFormatError("Values are nested too deeply.");
  const at = context.reader.at;
  const type = context.reader.u32();
  const simple = scalar(context, type);
  if (simple !== undefined) return simple;
  if (type === 26 || type === 30) return container(context, type, depth);
  if (type === 34) {
    const count = context.reader.u32();
    if (count * 4 > context.reader.bytes.length - context.reader.at)
      throw new GodotFormatError(`${String(count)} strings cannot fit.`);
    return {
      kind: "packed",
      type: engineNames(context.major).strings,
      items: Array.from({ length: count }, () => context.reader.text()),
      width: 1,
      single: false,
    };
  }
  const shape = math(context.major)[type];
  if (shape !== undefined) {
    const [name, count, kind] = shape;
    return {
      kind: "math",
      type: name,
      parts: Array.from({ length: count }, () => element(context, kind)),
      integer: kind === "int",
      single: kind === "float" || (kind === "real" && !context.real64),
    };
  }
  const array = packed(context.major)[type];
  if (array !== undefined) return packedArray(context, array);
  throw new GodotFormatError(
    `Value type ${String(type)} at ${String(at)} is not one Godot writes to binary resources.`,
  );
};
