import type { GodotFileReport } from "../domain/godot/godotFile.js";
import type { GodotResourceFile } from "./GodotResource.js";
import type { SceneTree } from "./GodotScene.js";
import { typeName, valueText, type GodotValue } from "./GodotValues.js";

/** Report rows for each view, before selection, query and paging. */

type Rows<K extends keyof GodotFileReport> = GodotFileReport[K];

const CONNECT_FLAGS: readonly (readonly [number, string])[] = [
  [1, "deferred"],
  [2, "persist"],
  [4, "one_shot"],
  [8, "reference_counted"],
  [16, "append_source_object"],
];

export const resourceRows = (file: GodotResourceFile): Rows<"resources"> => [
  ...file.external.map((external, index) => ({
    id: `ext:${String(index + 1)}`,
    kind: "external" as const,
    type: external.type,
    path: external.path,
    uid: external.uid,
    properties: 0,
    offset: null,
    error: null,
  })),
  ...file.resources.map((resource) => ({
    id: resource.id,
    kind: resource.id === "main" ? ("main" as const) : ("internal" as const),
    type: resource.type,
    path: null,
    uid: resource.id === "main" ? file.header.uid : null,
    properties: resource.properties.length,
    offset: resource.offset,
    error: resource.error,
  })),
];

const propertyRow = (
  ownerKind: "resource" | "node",
  owner: string,
  name: string,
  value: GodotValue,
): Rows<"properties">[number] => {
  const { text, truncated } = valueText(value);
  return {
    owner_kind: ownerKind,
    owner,
    name,
    type: typeName(value),
    value: text,
    truncated,
  };
};

/** Every stored property; a scene's packed _bundled is read as its nodes instead. */
export const propertyRows = (
  file: GodotResourceFile,
  scene: SceneTree | null,
): Rows<"properties"> => [
  ...(scene?.nodes.flatMap((node) =>
    node.properties.map(({ name, value }) =>
      propertyRow("node", node.path, name, value),
    ),
  ) ?? []),
  ...file.resources.flatMap((resource) =>
    resource.properties
      .filter(({ name }) => scene === null || name !== "_bundled")
      .map(({ name, value }) =>
        propertyRow("resource", resource.id, name, value),
      ),
  ),
];

export const nodeRows = (scene: SceneTree): Rows<"nodes"> =>
  scene.nodes.map((node) => ({
    index: node.index,
    path: node.path,
    parent: node.parent,
    type: node.type,
    instance:
      node.instance === null ? null : valueText(node.instance, 1000).text,
    placeholder: node.placeholder,
    groups: [...node.groups],
    properties: node.properties.length,
  }));

export const connectionRows = (scene: SceneTree): Rows<"connections"> =>
  scene.connections.map((connection) => ({
    from: connection.from,
    signal: connection.signal,
    to: connection.to,
    method: connection.method,
    flags: CONNECT_FLAGS.filter(([bit]) => (connection.flags & bit) !== 0).map(
      ([, name]) => name,
    ),
    binds: connection.binds.map((bind) => valueText(bind, 1000).text),
    unbinds: connection.unbinds,
  }));

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;

const childKey = (key: GodotValue): string => {
  if (
    (key.kind === "string" || key.kind === "string_name") &&
    IDENTIFIER.test(key.value)
  )
    return `.${key.value}`;
  return `[${valueText(key, 200).text}]`;
};

const children = (value: GodotValue): (readonly [string, GodotValue])[] => {
  if (value.kind === "array")
    return value.items.map((item, index) => [`[${String(index)}]`, item]);
  if (value.kind === "dictionary")
    return value.entries.map(([key, item]) => [childKey(key), item]);
  if (value.kind === "object" && value.reference === "inline")
    return value.properties.map(([name, item]) => [
      IDENTIFIER.test(name) ? `.${name}` : `[${JSON.stringify(name)}]`,
      item,
    ]);
  return [];
};

/** A save's values depth first, containers then their children. */
export const valueRows = (values: readonly GodotValue[]): Rows<"values"> => {
  const rows: Rows<"values">[number][] = [];
  const visit = (value: GodotValue, path: string, depth: number): void => {
    const kids = children(value);
    const container =
      value.kind === "array" ||
      value.kind === "dictionary" ||
      (value.kind === "object" && value.reference === "inline");
    const shown = valueText(value, container ? 1000 : 2000);
    rows.push({
      path,
      depth,
      type:
        value.kind === "object" && value.reference === "inline"
          ? value.target
          : typeName(value),
      value: shown.text,
      truncated: shown.truncated,
      children: kids.length,
    });
    for (const [key, child] of kids) visit(child, `${path}${key}`, depth + 1);
  };
  values.forEach((value, index) =>
    visit(value, values.length === 1 ? "$" : `$[${String(index)}]`, 0),
  );
  return rows;
};
