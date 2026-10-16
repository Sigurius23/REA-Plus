import type { BlobNode } from "./BlobTree.js";

/**
 * Paths that name one node: $ for the root, [i] for array items, .name or
 * ["name"] for keys, and .5 for protobuf field 5. A key that repeats among
 * its siblings (a repeated protobuf field) gets its occurrence: .5[1].
 */

export interface FlatNode {
  readonly path: string;
  readonly depth: number;
  readonly node: BlobNode;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const ORDERED = new Set(["array", "region"]);

const segment = (
  parent: BlobNode,
  child: BlobNode,
  occurrence: number | null,
): string => {
  const { key } = child;
  if (ORDERED.has(parent.type) || parent.type.startsWith("list<"))
    return `[${String(key)}]`;
  const name =
    typeof key === "number"
      ? `.${String(key)}`
      : IDENTIFIER.test(key ?? "")
        ? `.${key ?? ""}`
        : `[${JSON.stringify(key)}]`;
  return occurrence === null ? name : `${name}[${String(occurrence)}]`;
};

/** Depth-first rows under `root`, with paths relative to `base`. */
export const flatten = (root: BlobNode, base = "$", depth = 0): FlatNode[] => {
  const rows: FlatNode[] = [];
  const visit = (current: BlobNode, path: string, level: number) => {
    rows.push({ path, depth: level, node: current });
    const counts = new Map<BlobNode["key"], number>();
    for (const child of current.children)
      counts.set(child.key, (counts.get(child.key) ?? 0) + 1);
    const seen = new Map<BlobNode["key"], number>();
    for (const child of current.children) {
      const index = seen.get(child.key) ?? 0;
      seen.set(child.key, index + 1);
      const repeated =
        (counts.get(child.key) ?? 0) > 1 &&
        !ORDERED.has(current.type) &&
        !current.type.startsWith("list<");
      visit(
        child,
        `${path}${segment(current, child, repeated ? index : null)}`,
        level + 1,
      );
    }
  };
  visit(root, base, depth);
  return rows;
};
