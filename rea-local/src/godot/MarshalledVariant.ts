import { GodotFormatError, Reader, utf8 } from "./GodotBytes.js";
import { engineNames, NIL, type GodotValue } from "./GodotValues.js";

/**
 * Variants as Godot's marshalls.cpp encodes them: script constants in
 * compiled GDScript, var_to_bytes / var2bytes, and store_var save files.
 * Godot 3 and Godot 4 number the types differently.
 */

const FLAG_64 = 1 << 16;
const MAX_DEPTH = 1024;

type Element = "real" | "float" | "int" | "int64" | "double" | "byte";
type Shape =
  | readonly ["nil" | "bool" | "int" | "float" | "string" | "string_name"]
  | readonly ["node_path" | "rid" | "object" | "callable" | "signal"]
  | readonly ["dictionary" | "array" | "strings"]
  | readonly ["math", string, number, Element]
  | readonly ["packed", string, number, Element];

const GODOT4: readonly Shape[] = [
  ["nil"],
  ["bool"],
  ["int"],
  ["float"],
  ["string"],
  ["math", "Vector2", 2, "real"],
  ["math", "Vector2i", 2, "int"],
  ["math", "Rect2", 4, "real"],
  ["math", "Rect2i", 4, "int"],
  ["math", "Vector3", 3, "real"],
  ["math", "Vector3i", 3, "int"],
  ["math", "Transform2D", 6, "real"],
  ["math", "Vector4", 4, "real"],
  ["math", "Vector4i", 4, "int"],
  ["math", "Plane", 4, "real"],
  ["math", "Quaternion", 4, "real"],
  ["math", "AABB", 6, "real"],
  ["math", "Basis", 9, "real"],
  ["math", "Transform3D", 12, "real"],
  ["math", "Projection", 16, "real"],
  ["math", "Color", 4, "float"],
  ["string_name"],
  ["node_path"],
  ["rid"],
  ["object"],
  ["callable"],
  ["signal"],
  ["dictionary"],
  ["array"],
  ["packed", "PackedByteArray", 1, "byte"],
  ["packed", "PackedInt32Array", 1, "int"],
  ["packed", "PackedInt64Array", 1, "int64"],
  ["packed", "PackedFloat32Array", 1, "float"],
  ["packed", "PackedFloat64Array", 1, "double"],
  ["strings"],
  ["packed", "PackedVector2Array", 2, "real"],
  ["packed", "PackedVector3Array", 3, "real"],
  ["packed", "PackedColorArray", 4, "float"],
  ["packed", "PackedVector4Array", 4, "real"],
];

const names3 = engineNames(3);
const GODOT3: readonly Shape[] = [
  ["nil"],
  ["bool"],
  ["int"],
  ["float"],
  ["string"],
  ["math", "Vector2", 2, "float"],
  ["math", "Rect2", 4, "float"],
  ["math", "Vector3", 3, "float"],
  ["math", "Transform2D", 6, "float"],
  ["math", "Plane", 4, "float"],
  ["math", names3.quaternion, 4, "float"],
  ["math", "AABB", 6, "float"],
  ["math", "Basis", 9, "float"],
  ["math", names3.transform3d, 12, "float"],
  ["math", "Color", 4, "float"],
  ["node_path"],
  ["rid"],
  ["object"],
  ["dictionary"],
  ["array"],
  ["packed", names3.bytes, 1, "byte"],
  ["packed", names3.int32, 1, "int"],
  ["packed", names3.float32, 1, "float"],
  ["strings"],
  ["packed", names3.vector2s, 2, "float"],
  ["packed", names3.vector3s, 3, "float"],
  ["packed", names3.colors, 4, "float"],
];

const TYPE_NAMES4 = GODOT4.map((shape) =>
  shape[0] === "math" || shape[0] === "packed"
    ? shape[1]
    : ({
        nil: "Nil",
        bool: "bool",
        int: "int",
        float: "float",
        string: "String",
        string_name: "StringName",
        node_path: "NodePath",
        rid: "RID",
        object: "Object",
        callable: "Callable",
        signal: "Signal",
        dictionary: "Dictionary",
        array: "Array",
        strings: "PackedStringArray",
      }[shape[0]] ?? "?"),
);

class Decoder {
  readonly reader: Reader;

  constructor(
    bytes: Buffer,
    readonly major: 3 | 4,
  ) {
    this.reader = new Reader(bytes);
  }

  string(): string {
    const length = this.reader.u32();
    const text = utf8(this.reader.take(length, "string"));
    this.reader.need((4 - (length % 4)) % 4, "padding");
    return text;
  }

  element(kind: Element, wide: boolean): number | bigint {
    const { reader } = this;
    if (kind === "int") return reader.i32();
    if (kind === "int64") return reader.i64();
    if (kind === "double") return reader.f64();
    if (kind === "byte") return reader.u8();
    if (kind === "real" && wide) return reader.f64();
    return reader.f32();
  }

  /** Godot 4 typed containers name their element type before the count. */
  containerType(kind: number): string | null {
    if (kind === 0) return null;
    if (kind === 1) {
      const type = this.reader.u32();
      return TYPE_NAMES4[type] ?? `type ${String(type)}`;
    }
    if (kind === 2) return this.string();
    if (kind === 3) return `Script(${this.string()})`;
    throw new GodotFormatError(
      `Container type kind ${String(kind)} is unknown.`,
    );
  }

  count(what: string): number {
    const count = this.reader.u32() & 0x7fffffff;
    if (count > this.reader.bytes.length - this.reader.at)
      throw new GodotFormatError(
        `A ${what} of ${String(count)} entries cannot fit.`,
      );
    return count;
  }

  container(kind: "dictionary" | "array", header: number, depth: number) {
    const four = this.major === 4;
    if (kind === "array") {
      const typed = four ? this.containerType((header >> 16) & 3) : null;
      const count = this.count("array");
      return {
        kind,
        typed,
        items: Array.from({ length: count }, () => this.value(depth + 1)),
      } as const;
    }
    const key = four ? this.containerType((header >> 16) & 3) : null;
    const value = four ? this.containerType((header >> 18) & 3) : null;
    const count = this.count("dictionary");
    return {
      kind,
      typed:
        key === null && value === null
          ? null
          : `${key ?? "Variant"}, ${value ?? "Variant"}`,
      entries: Array.from(
        { length: count },
        () => [this.value(depth + 1), this.value(depth + 1)] as const,
      ),
    } as const;
  }

  nodePath(): GodotValue {
    const head = this.reader.u32();
    if ((head & 0x80000000) === 0)
      throw new GodotFormatError("NodePath in the pre-3.0 format.");
    const names = head & 0x7fffffff;
    const subnames = this.reader.u32();
    const flags = this.reader.u32();
    const total = names + subnames + ((flags & 2) === 0 ? 0 : 1);
    const parts = Array.from({ length: total }, () => this.string());
    return {
      kind: "node_path",
      value: `${(flags & 1) === 0 ? "" : "/"}${parts.slice(0, names).join("/")}${parts
        .slice(names)
        .map((name) => `:${name}`)
        .join("")}`,
    };
  }

  object(header: number, depth: number): GodotValue {
    const none: GodotValue = {
      kind: "object",
      reference: "null",
      target: "",
      properties: [],
    };
    if ((header & FLAG_64) !== 0) {
      const id = this.reader.u64();
      return id === 0n
        ? none
        : {
            kind: "object",
            reference: "id",
            target: String(id),
            properties: [],
          };
    }
    const type = this.string();
    if (type === "") return none;
    const count = this.count("object");
    return {
      kind: "object",
      reference: "inline",
      target: type,
      properties: Array.from(
        { length: count },
        () => [this.string(), this.value(depth + 1)] as const,
      ),
    };
  }

  scalar(shape: Shape, header: number, depth: number): GodotValue {
    const wide = (header & FLAG_64) !== 0;
    const { reader } = this;
    switch (shape[0]) {
      case "nil":
        return NIL;
      case "bool":
        return { kind: "bool", value: reader.u32() !== 0 };
      case "int":
        return {
          kind: "int",
          value: wide ? reader.i64() : BigInt(reader.i32()),
        };
      case "float":
        return {
          kind: "float",
          value: wide ? reader.f64() : reader.f32(),
          single: !wide,
        };
      case "string":
      case "string_name":
        return { kind: shape[0], value: this.string() };
      case "node_path":
        return this.nodePath();
      case "rid":
        if (this.major === 3) return { kind: "opaque", type: "RID", value: "" };
        return { kind: "opaque", type: "RID", value: String(reader.u64()) };
      case "object":
        return this.object(header, depth);
      case "callable":
        return { kind: "opaque", type: "Callable", value: "" };
      case "signal": {
        const name = this.string();
        return {
          kind: "opaque",
          type: "Signal",
          value: `${name}, #${String(reader.u64())}`,
        };
      }
      default:
        return this.container(
          shape[0] as "dictionary" | "array",
          header,
          depth,
        );
    }
  }

  value(depth = 0): GodotValue {
    if (depth > MAX_DEPTH)
      throw new GodotFormatError("Values are nested too deeply.");
    const at = this.reader.at;
    const header = this.reader.u32();
    const shape = (this.major === 4 ? GODOT4 : GODOT3)[header & 0xff];
    if (shape === undefined)
      throw new GodotFormatError(
        `Type ${String(header & 0xff)} at ${String(at)} is not a Godot ${String(this.major)} Variant type.`,
      );
    const wide = (header & FLAG_64) !== 0;
    if (shape[0] === "math") {
      const [, type, count, kind] = shape;
      return {
        kind: "math",
        type,
        parts: Array.from({ length: count }, () =>
          Number(this.element(kind, wide)),
        ),
        integer: kind === "int",
        single: kind === "float" || !wide,
      };
    }
    if (shape[0] === "packed") {
      const [, type, width, kind] = shape;
      const count = this.count(type) * width;
      const items = Array.from({ length: count }, () =>
        this.element(kind, wide),
      );
      if (kind === "byte") this.reader.need((4 - (count % 4)) % 4, "padding");
      return {
        kind: "packed",
        type,
        items,
        width,
        single: kind === "float" || (kind === "real" && !wide),
      };
    }
    if (shape[0] === "strings") {
      const count = this.count("string array");
      const type = this.major === 4 ? "PackedStringArray" : names3.strings;
      return {
        kind: "packed",
        type,
        items: Array.from({ length: count }, () => this.string()),
        width: 1,
        single: false,
      };
    }
    return this.scalar(shape, header, depth);
  }
}

/** One Variant at `offset`, and the bytes it used. */
export const marshalledVariant = (
  bytes: Buffer,
  major: 3 | 4,
  offset = 0,
): { readonly value: GodotValue; readonly length: number } => {
  const decoder = new Decoder(bytes, major);
  decoder.reader.at = offset;
  const value = decoder.value();
  return { value, length: decoder.reader.at - offset };
};

export type VariantEncoding = "store_var" | "var_to_bytes" | "project_settings";

/**
 * project.binary (ECFG): a count, then each setting's key and its value,
 * both length-prefixed. Read as one dictionary of "section/key" names.
 */
const projectSettings = (bytes: Buffer, major: 3 | 4): GodotValue => {
  const reader = new Reader(bytes, 4);
  const count = reader.u32();
  if (count * 8 > bytes.length)
    throw new GodotFormatError(`${String(count)} settings cannot fit.`);
  const entries = Array.from({ length: count }, () => {
    const key = utf8(reader.take(reader.u32(), "setting name"));
    const length = reader.u32();
    const end = reader.at + length;
    const { value, length: used } = marshalledVariant(
      bytes.subarray(0, end),
      major,
      reader.at,
    );
    if (used !== length)
      throw new GodotFormatError(
        `Setting ${key} uses ${String(used)} of its ${String(length)} bytes.`,
      );
    reader.at = end;
    return [{ kind: "string", value: key }, value] as const;
  });
  if (reader.at !== bytes.length)
    throw new GodotFormatError(
      `The settings end at ${String(reader.at)} of ${String(bytes.length)} bytes.`,
    );
  return { kind: "dictionary", typed: null, entries };
};

/** A store_var file: each value is a u32 length then the Variant, using every byte. */
const prefixedValues = (bytes: Buffer, major: 3 | 4): GodotValue[] => {
  const values: GodotValue[] = [];
  let at = 0;
  while (at < bytes.length) {
    if (at + 4 > bytes.length)
      throw new GodotFormatError("A length prefix runs past the end.");
    const length = bytes.readUInt32LE(at);
    const { value, length: used } = marshalledVariant(
      bytes.subarray(0, at + 4 + length),
      major,
      at + 4,
    );
    if (used !== length)
      throw new GodotFormatError(
        `The value at ${String(at)} uses ${String(used)} of its ${String(length)} bytes.`,
      );
    values.push(value);
    at += 4 + length;
  }
  return values;
};

/**
 * Godot's own Variant files: project.binary settings, store_var saves
 * (length-prefixed values), or a single var_to_bytes value.
 */
export const variantStream = (
  bytes: Buffer,
  major: 3 | 4,
): {
  readonly values: readonly GodotValue[];
  readonly encoding: VariantEncoding;
} => {
  if (bytes.subarray(0, 4).toString("latin1") === "ECFG")
    return {
      values: [projectSettings(bytes, major)],
      encoding: "project_settings",
    };
  try {
    const values = prefixedValues(bytes, major);
    if (values.length > 0) return { values, encoding: "store_var" };
  } catch (cause) {
    if (!(cause instanceof GodotFormatError)) throw cause;
  }
  const { value, length } = marshalledVariant(bytes, major);
  if (length !== bytes.length)
    throw new GodotFormatError(
      `A Godot ${String(major)} value ends at ${String(length)} of ${String(bytes.length)} bytes.`,
    );
  return { values: [value], encoding: "var_to_bytes" };
};
