import type { GodotFileReport } from "../../../src/domain/godot/godotFile.js";
import { sameGodotText } from "./godotText.js";

/**
 * Compare inspect_godot_file with what Godot 3 itself read back from the
 * files GODOT3_GENERATOR wrote (out/reference.json).
 */

type Inspect = (input: Record<string, unknown>) => Promise<GodotFileReport>;
type View = GodotFileReport["page"]["view"];
type Row<V extends View> = GodotFileReport[V][number];

interface ReferenceProperty {
  readonly value: string;
  /** Whether the value equals a fresh instance's; Godot does not store those. */
  readonly default: boolean;
}

export interface ReferenceEntry {
  readonly type?: string;
  readonly resources?: Readonly<
    Record<string, Readonly<Record<string, ReferenceProperty>>>
  >;
  readonly nodes?: readonly {
    readonly path: string;
    readonly type: string;
    readonly instance: string | null;
    readonly groups: readonly string[];
    readonly properties: Readonly<Record<string, string>>;
  }[];
  readonly connections?: readonly {
    readonly from: string;
    readonly signal: string;
    readonly to: string;
    readonly method: string;
    readonly flags: number;
    readonly binds: readonly string[];
  }[];
  readonly values?: readonly string[];
  readonly password?: string;
  readonly key?: string;
}

/** Every row of a view, page by page. */
export const allRows = async <V extends View>(
  inspect: Inspect,
  input: Record<string, unknown>,
  view: V,
): Promise<Row<V>[]> => {
  const rows: Row<V>[] = [];
  for (let offset = 0; ; offset += 1000) {
    const report = await inspect({ ...input, view, offset, limit: 1000 });
    rows.push(...(report[view] as Row<V>[]));
    if (offset + 1000 >= report.page.total) return rows;
  }
};

/** Godot prints an unnamed sub-resource (Godot 3 leaves Image paths empty) as SubResource(?). */
const same = (ours: string, godot: string): boolean =>
  godot === "SubResource(?)"
    ? ours.startsWith("SubResource(")
    : sameGodotText(ours, godot);

const relative = (path: string): string => path.replace(/^\.\//u, "");

const FLAGS = ["deferred", "persist", "one_shot", "reference_counted"];

const resourceProblems = (
  name: string,
  rows: readonly Row<"properties">[],
  resources: NonNullable<ReferenceEntry["resources"]>,
  scene: boolean,
): string[] =>
  Object.entries(resources).flatMap(([id, godot]) => {
    const ours = rows.filter(
      (row) => row.owner_kind === "resource" && row.owner === id,
    );
    const wrong = ours.flatMap((row) => {
      const expected = godot[row.name];
      if (expected === undefined)
        return [`${name} ${id}.${row.name}: Godot has no such property`];
      return same(row.value, expected.value)
        ? []
        : [`${name} ${id}.${row.name}: ${row.value} != ${expected.value}`];
    });
    // A scene's main resource keeps its nodes in _bundled, compared below.
    const missing = Object.entries(godot)
      .filter(
        ([prop, expected]) =>
          !expected.default &&
          !(scene && id === "main") &&
          !ours.some((row) => row.name === prop),
      )
      .map(
        ([prop, expected]) =>
          `${name} ${id}.${prop}: not read (Godot: ${expected.value})`,
      );
    return [...wrong, ...missing];
  });

const sceneProblems = (
  name: string,
  ours: {
    readonly nodes: readonly Row<"nodes">[];
    readonly properties: readonly Row<"properties">[];
    readonly connections: readonly Row<"connections">[];
  },
  entry: ReferenceEntry,
): string[] => {
  const { nodes, properties, connections } = ours;
  const problems: string[] = [];
  if (nodes.length !== entry.nodes?.length)
    problems.push(
      `${name}: ${String(nodes.length)} nodes, Godot ${String(entry.nodes?.length)}`,
    );
  entry.nodes?.forEach((godot, index) => {
    const node = nodes[index];
    const shape = node && [
      node.path,
      node.type ?? "",
      node.instance,
      node.groups.join(),
    ];
    if (
      JSON.stringify(shape) !==
      JSON.stringify([
        relative(godot.path),
        godot.type,
        godot.instance,
        godot.groups.join(),
      ])
    )
      problems.push(
        `${name} node ${String(index)}: ${JSON.stringify(node)} != ${JSON.stringify(godot)}`,
      );
    const ours = properties.filter(
      (row) => row.owner_kind === "node" && row.owner === node?.path,
    );
    if (ours.length !== Object.keys(godot.properties).length)
      problems.push(
        `${name} ${godot.path}: properties ${ours.map((row) => row.name).join()}`,
      );
    for (const row of ours)
      if (!same(row.value, godot.properties[row.name] ?? ""))
        problems.push(`${name} ${godot.path}.${row.name}: ${row.value}`);
  });
  entry.connections?.forEach((godot, index) => {
    const ours = connections[index];
    const flags = FLAGS.filter((_, bit) => (godot.flags & (1 << bit)) !== 0);
    const matches =
      ours !== undefined &&
      [ours.from, ours.signal, ours.to, ours.method, ours.flags.join()].join(
        "|",
      ) ===
        [
          relative(godot.from),
          godot.signal,
          relative(godot.to),
          godot.method,
          flags.join(),
        ].join("|") &&
      ours.binds.length === godot.binds.length &&
      ours.binds.every((bind, at) => same(bind, godot.binds[at] ?? ""));
    if (!matches)
      problems.push(
        `${name} connection ${String(index)}: ${JSON.stringify(ours)} != ${JSON.stringify(godot)}`,
      );
  });
  return problems;
};

/** Problems with one generated file, and how many values were compared. */
export const entryProblems = async (
  inspect: Inspect,
  file: string,
  name: string,
  entry: ReferenceEntry,
): Promise<{ readonly checked: number; readonly problems: string[] }> => {
  if (entry.values !== undefined) {
    const keys = {
      ...(entry.password === undefined
        ? {}
        : { password_env: "GODOT3_PASSWORD" }),
      ...(entry.key === undefined ? {} : { key_env: "GODOT3_KEY" }),
    };
    const top = (
      await allRows(inspect, { path: file, ...keys }, "values")
    ).filter(({ depth }) => depth === 0);
    const problems = entry.values.flatMap((godot, index) => {
      const row = top[index];
      if (row === undefined) return [`${name}: value ${String(index)} missing`];
      // Long values are cut; the bytes themselves are compared separately.
      if (row.truncated || row.value === null) return [];
      return same(row.value, godot)
        ? []
        : [`${name} value ${String(index)}: ${row.value} != ${godot}`];
    });
    if (top.length !== entry.values.length)
      problems.push(
        `${name}: ${String(top.length)} values, Godot ${String(entry.values.length)}`,
      );
    return { checked: top.length, problems };
  }
  const properties = await allRows(inspect, { path: file }, "properties");
  const problems = resourceProblems(
    name,
    properties,
    entry.resources ?? {},
    entry.nodes !== undefined,
  );
  if (entry.nodes !== undefined) {
    const nodes = await allRows(inspect, { path: file }, "nodes");
    const connections = await allRows(inspect, { path: file }, "connections");
    problems.push(
      ...sceneProblems(name, { nodes, properties, connections }, entry),
    );
  }
  return {
    checked:
      properties.length +
      (entry.nodes?.length ?? 0) +
      (entry.connections?.length ?? 0),
    problems,
  };
};
