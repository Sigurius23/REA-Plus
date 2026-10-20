import { floatText, quoted, realText } from "./GodotBytes.js";

/**
 * A Variant read from a binary resource, a script constant or a save
 * written with store_var. Type names follow the engine that wrote it
 * (PoolIntArray in Godot 3, PackedInt32Array in Godot 4).
 */
export type GodotValue =
  | { readonly kind: "nil" }
  | { readonly kind: "bool"; readonly value: boolean }
  | { readonly kind: "int"; readonly value: bigint }
  | { readonly kind: "float"; readonly value: number; readonly single: boolean }
  | {
      readonly kind: "string" | "string_name" | "node_path";
      readonly value: string;
    }
  | {
      readonly kind: "math";
      readonly type: string;
      readonly parts: readonly number[];
      readonly integer: boolean;
      readonly single: boolean;
    }
  | {
      readonly kind: "object";
      readonly reference: "external" | "internal" | "null" | "id" | "inline";
      readonly target: string;
      readonly properties: readonly (readonly [string, GodotValue])[];
    }
  | { readonly kind: "opaque"; readonly type: string; readonly value: string }
  | {
      readonly kind: "dictionary";
      readonly entries: readonly (readonly [GodotValue, GodotValue])[];
      readonly typed: string | null;
    }
  | {
      readonly kind: "array";
      readonly items: readonly GodotValue[];
      readonly typed: string | null;
    }
  | {
      readonly kind: "packed";
      readonly type: string;
      readonly items: readonly (number | bigint | string)[];
      readonly width: number;
      readonly single: boolean;
    };

export const NIL: GodotValue = { kind: "nil" };

/** The type name Godot would report for the value. */
export const typeName = (value: GodotValue): string => {
  switch (value.kind) {
    case "nil":
      return "null";
    case "bool":
      return "bool";
    case "int":
      return "int";
    case "float":
      return "float";
    case "string":
      return "String";
    case "string_name":
      return "StringName";
    case "node_path":
      return "NodePath";
    case "object":
      return value.reference === "null" ? "Object" : "Resource";
    case "dictionary":
      return "Dictionary";
    case "array":
      return "Array";
    default:
      return value.type;
  }
};

/** Collects text up to a budget, so huge meshes or saves stay bounded. */
class Writer {
  text = "";
  full = false;

  constructor(readonly budget: number) {}

  put(text: string): boolean {
    if (this.full) return false;
    if (this.text.length + text.length > this.budget) {
      this.text += text.slice(0, Math.max(0, this.budget - this.text.length));
      this.text += "…";
      this.full = true;
      return false;
    }
    this.text += text;
    return true;
  }
}

const item = (
  value: number | bigint | string,
  single: boolean,
  integer: boolean,
): string => {
  if (typeof value === "string") return quoted(value);
  if (typeof value === "bigint" || integer) return String(value);
  return realText(value, single);
};

const packed = (
  value: Extract<GodotValue, { kind: "packed" }>,
  out: Writer,
): void => {
  const integer = /Byte|Int/u.test(value.type);
  out.put(`${value.type}(`);
  value.items.every((part, index) =>
    out.put(`${index === 0 ? "" : ", "}${item(part, value.single, integer)}`),
  );
  out.put(")");
};

const objectText = (
  value: Extract<GodotValue, { kind: "object" }>,
  out: Writer,
): void => {
  if (value.reference === "null") out.put("null");
  else if (value.reference === "external")
    out.put(`ExtResource(${quoted(value.target)})`);
  else if (value.reference === "internal")
    out.put(`SubResource(${quoted(value.target)})`);
  else if (value.reference === "id") out.put(`Object(#${value.target})`);
  else {
    out.put(`Object(${value.target}`);
    for (const [name, property] of value.properties) {
      if (!out.put(`, ${quoted(name)}: `)) break;
      write(property, out);
    }
    out.put(")");
  }
};

const containerText = (
  value: Extract<GodotValue, { kind: "dictionary" | "array" }>,
  out: Writer,
): void => {
  const typed = value.typed === null ? "" : `[${value.typed}]`;
  if (value.kind === "array") {
    out.put(typed === "" ? "[" : `Array${typed}([`);
    value.items.every((entry, index) => {
      if (index > 0 && !out.put(", ")) return false;
      write(entry, out);
      return !out.full;
    });
    out.put(typed === "" ? "]" : "])");
    return;
  }
  out.put(typed === "" ? "{" : `Dictionary${typed}({`);
  value.entries.every(([key, entry], index) => {
    if (index > 0 && !out.put(", ")) return false;
    write(key, out);
    out.put(": ");
    write(entry, out);
    return !out.full;
  });
  out.put(typed === "" ? "}" : "})");
};

const write = (value: GodotValue, out: Writer): void => {
  switch (value.kind) {
    case "nil":
      out.put("null");
      return;
    case "bool":
    case "int":
      out.put(String(value.value));
      return;
    case "float":
      out.put(floatText(value.value, value.single));
      return;
    case "string":
      out.put(quoted(value.value));
      return;
    case "string_name":
      out.put(`&${quoted(value.value)}`);
      return;
    case "node_path":
      out.put(`NodePath(${quoted(value.value)})`);
      return;
    case "math":
      out.put(
        `${value.type}(${value.parts.map((part) => item(part, value.single, value.integer)).join(", ")})`,
      );
      return;
    case "object":
      objectText(value, out);
      return;
    case "opaque":
      out.put(`${value.type}(${value.value})`);
      return;
    case "packed":
      packed(value, out);
      return;
    default:
      containerText(value, out);
  }
};

/** The value as Godot's text resource format writes it, cut at `budget` characters. */
export const valueText = (
  value: GodotValue,
  budget = 4000,
): { readonly text: string; readonly truncated: boolean } => {
  const out = new Writer(budget);
  write(value, out);
  return { text: out.text, truncated: out.full };
};

/** Godot 3 and Godot 4 names for the same stored type codes. */
export const engineNames = (major: number) =>
  major >= 4
    ? {
        quaternion: "Quaternion",
        transform3d: "Transform3D",
        bytes: "PackedByteArray",
        int32: "PackedInt32Array",
        float32: "PackedFloat32Array",
        strings: "PackedStringArray",
        vector2s: "PackedVector2Array",
        vector3s: "PackedVector3Array",
        colors: "PackedColorArray",
      }
    : {
        quaternion: "Quat",
        transform3d: "Transform",
        bytes: "PoolByteArray",
        int32: "PoolIntArray",
        float32: "PoolRealArray",
        strings: "PoolStringArray",
        vector2s: "PoolVector2Array",
        vector3s: "PoolVector3Array",
        colors: "PoolColorArray",
      };
