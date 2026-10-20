import { GodotFormatError } from "./GodotBytes.js";
import type { GodotValue } from "./GodotValues.js";

/**
 * A PackedScene's _bundled dictionary (SceneState::set_bundled_scene in
 * Godot 3 and 4): node and connection records packed into int arrays that
 * index a names table and a variants table.
 */

const NO_PARENT = 0x7fffffff;
const ID_IS_PATH = 1 << 30;
const FLAG_MASK = (1 << 24) - 1;
const NAME_BITS = 18;
const TYPE_INSTANTIATED = 0x7fffffff;
const PLACEHOLDER = 1 << 30;
const PROPERTY_NAME_MASK = (1 << 30) - 1;

export interface SceneNode {
  readonly index: number;
  readonly path: string;
  readonly parent: string | null;
  readonly type: string | null;
  /** The scene this node instances (an ExtResource), or a placeholder's path. */
  readonly instance: GodotValue | null;
  readonly placeholder: boolean;
  readonly groups: readonly string[];
  readonly properties: readonly {
    readonly name: string;
    readonly value: GodotValue;
  }[];
}

export interface SceneConnection {
  readonly from: string;
  readonly signal: string;
  readonly to: string;
  readonly method: string;
  readonly flags: number;
  readonly binds: readonly GodotValue[];
  readonly unbinds: number;
}

export interface SceneTree {
  readonly version: number;
  readonly nodes: readonly SceneNode[];
  readonly connections: readonly SceneConnection[];
  readonly editableInstances: readonly string[];
  readonly baseScene: GodotValue | null;
  /** Whether the node and connection arrays were used to the last value. */
  readonly exact: boolean;
}

const field = (bundle: GodotValue, key: string): GodotValue | undefined =>
  bundle.kind === "dictionary"
    ? bundle.entries.find(
        ([name]) =>
          (name.kind === "string" || name.kind === "string_name") &&
          name.value === key,
      )?.[1]
    : undefined;

const ints = (value: GodotValue | undefined): number[] =>
  value?.kind === "packed" ? value.items.map(Number) : [];

const int = (value: GodotValue | undefined, fallback: number): number =>
  value?.kind === "int" ? Number(value.value) : fallback;

const list = (value: GodotValue | undefined): readonly GodotValue[] => {
  if (value?.kind === "array") return value.items;
  if (value?.kind === "packed")
    return value.items.map((item) => ({ kind: "string", value: String(item) }));
  return [];
};

const text = (value: GodotValue | undefined): string =>
  value !== undefined && "value" in value ? String(value.value) : "";

/** Reads the int arrays in order, refusing to run past them. */
class Cursor {
  at = 0;

  constructor(
    readonly values: readonly number[],
    readonly what: string,
  ) {}

  next(): number {
    const value = this.values[this.at];
    if (value === undefined)
      throw new GodotFormatError(`The scene's ${this.what} array ends early.`);
    this.at += 1;
    return value;
  }

  /** A count, then that many groups of `width` values. */
  many(width = 1): number[] {
    const count = this.next() * width;
    if (count < 0 || count > this.values.length - this.at)
      throw new GodotFormatError(`The scene's ${this.what} array ends early.`);
    return Array.from({ length: count }, () => this.next());
  }
}

interface RawNode {
  readonly parent: number;
  readonly type: number;
  readonly name: number;
  readonly instance: number;
  readonly properties: readonly number[];
  readonly groups: readonly number[];
}

const rawNodes = (cursor: Cursor, count: number): RawNode[] =>
  Array.from({ length: count }, () => {
    const parent = cursor.next();
    cursor.next(); // owner
    const type = cursor.next();
    const name = cursor.next() & ((1 << NAME_BITS) - 1);
    const instance = cursor.next();
    // Property name and value indexes, interleaved.
    const properties = cursor.many(2);
    return {
      parent,
      type,
      name,
      instance,
      properties,
      groups: cursor.many(),
    };
  });

/** Decode a PackedScene's _bundled value into nodes and connections. */
export const readScene = (bundle: GodotValue): SceneTree => {
  const names = list(field(bundle, "names")).map(text);
  const variants = list(field(bundle, "variants"));
  const nodePaths = list(field(bundle, "node_paths")).map(text);
  const version = int(field(bundle, "version"), 1);
  const name = (index: number): string => names[index] ?? `#${String(index)}`;
  const variant = (index: number): GodotValue =>
    variants[index] ?? {
      kind: "opaque",
      type: "missing",
      value: String(index),
    };
  const nodeCursor = new Cursor(ints(field(bundle, "nodes")), "nodes");
  const raw = rawNodes(nodeCursor, int(field(bundle, "node_count"), 0));
  const paths: string[] = [];
  const pathOf = (index: number, seen = 0): string => {
    const node = raw[index];
    if (node === undefined || seen > raw.length)
      throw new GodotFormatError(`Scene node ${String(index)} does not exist.`);
    if (node.parent < 0 || node.parent === NO_PARENT) return ".";
    const own = name(node.name);
    if ((node.parent & ID_IS_PATH) !== 0)
      return `${nodePaths[node.parent & FLAG_MASK] ?? "?"}/${own}`;
    const parent = pathOf(node.parent & FLAG_MASK, seen + 1);
    return parent === "." ? own : `${parent}/${own}`;
  };
  raw.forEach((_, index) => paths.push(pathOf(index)));
  const nodes = raw.map((node, index): SceneNode => {
    const rooted = node.parent < 0 || node.parent === NO_PARENT;
    const parent = rooted
      ? null
      : (node.parent & ID_IS_PATH) !== 0
        ? (nodePaths[node.parent & FLAG_MASK] ?? "?")
        : (paths[node.parent & FLAG_MASK] ?? "?");
    const properties: { name: string; value: GodotValue }[] = [];
    for (let at = 0; at < node.properties.length; at += 2)
      properties.push({
        name: name((node.properties[at] ?? 0) & PROPERTY_NAME_MASK),
        value: variant(node.properties[at + 1] ?? 0),
      });
    return {
      index,
      path: paths[index] ?? "?",
      parent,
      type: node.type === TYPE_INSTANTIATED ? null : name(node.type),
      instance: node.instance < 0 ? null : variant(node.instance & FLAG_MASK),
      placeholder: node.instance >= 0 && (node.instance & PLACEHOLDER) !== 0,
      groups: node.groups.map(name),
      properties,
    };
  });
  const target = (id: number): string =>
    (id & ID_IS_PATH) !== 0
      ? (nodePaths[id & FLAG_MASK] ?? "?")
      : (paths[id & FLAG_MASK] ?? "?");
  const cursor = new Cursor(ints(field(bundle, "conns")), "connections");
  const connections = Array.from(
    { length: int(field(bundle, "conn_count"), 0) },
    (): SceneConnection => ({
      from: target(cursor.next()),
      to: target(cursor.next()),
      signal: name(cursor.next()),
      method: name(cursor.next()),
      flags: cursor.next(),
      binds: cursor.many().map(variant),
      unbinds: version >= 3 ? cursor.next() : 0,
    }),
  );
  const base = int(field(bundle, "base_scene"), -1);
  return {
    version,
    nodes,
    connections,
    editableInstances: list(field(bundle, "editable_instances")).map(text),
    baseScene: base >= 0 ? variant(base) : null,
    exact:
      nodeCursor.at === nodeCursor.values.length &&
      cursor.at === cursor.values.length,
  };
};
