import {
  DIFF_LISTING_LIMIT,
  DIFF_METHODS,
  type BinaryDiffReport,
  type DiffBinariesInput,
  type DiffListingRow,
  type DiffPairRow,
  type DiffUnmatchedRow,
} from "../domain/bindiff/binaryDiff.js";
import type { FunctionInventory } from "./BinaryDiffCollector.js";
import type { FunctionFeatures } from "./BinaryDiffFeatures.js";
import { editScript } from "./BinaryDiffEdits.js";
import type { FunctionMatch, matchFunctions } from "./BinaryDiffMatcher.js";
import { compositeKey } from "../domain/unicodeCodePointOrder.js";

/** Items listed per added or removed call, string or constant. */
const LIST_LIMIT = 16;

const difference = (left: readonly string[], right: readonly string[]) => {
  const set = new Set(right);
  return left.filter((item) => !set.has(item)).slice(0, LIST_LIMIT);
};

/** Multiset difference sizes, when no edit script was computed. */
const unmatchedCounts = (left: readonly string[], right: readonly string[]) => {
  const counts = new Map<string, number>();
  for (const item of left) counts.set(item, (counts.get(item) ?? 0) + 1);
  let shared = 0;
  for (const item of right) {
    const remaining = counts.get(item) ?? 0;
    if (remaining > 0) {
      shared += 1;
      counts.set(item, remaining - 1);
    }
  }
  return { removed: left.length - shared, added: right.length - shared };
};

const isIdentical = ({ left, right }: FunctionMatch) =>
  left.exactHash === right.exactHash &&
  compositeKey(left.strings) === compositeKey(right.strings) &&
  compositeKey(left.calleeNames) === compositeKey(right.calleeNames);

const ref = ({ address, name }: FunctionFeatures) => ({ address, name });

/** One matched pair, with calls compared through the match itself. */
export const pairRow = (
  match: FunctionMatch,
  partner: ReadonlyMap<string, FunctionFeatures>,
  leftByAddress: ReadonlyMap<string, FunctionFeatures>,
  rightByAddress: ReadonlyMap<string, FunctionFeatures>,
): DiffPairRow => {
  const { left, right } = match;
  const identical = isIdentical(match);
  const edits = identical ? [] : editScript(left.normalized, right.normalized);
  const lines =
    edits === null
      ? unmatchedCounts(left.normalized, right.normalized)
      : {
          removed: edits.filter((edit) => edit === "removed").length,
          added: edits.filter((edit) => edit === "added").length,
        };
  const mapped = new Set(
    left.callees.map((address) => partner.get(address)?.address ?? ""),
  );
  const rightCallees = new Set(right.callees);
  const name = (
    table: ReadonlyMap<string, FunctionFeatures>,
    address: string,
  ) => table.get(address)?.name ?? address;
  return {
    left: ref(left),
    right: ref(right),
    status: identical ? "identical" : "changed",
    method: match.method,
    similarity: Math.round(match.similarity * 1000) / 1000,
    call_graph_agreement:
      match.agreement === null
        ? null
        : Math.round(match.agreement * 1000) / 1000,
    instructions: [left.normalized.length, right.normalized.length],
    blocks: [left.blocks, right.blocks],
    edges: [left.edges, right.edges],
    lines_added: lines.added,
    lines_removed: lines.removed,
    calls_added: right.callees
      .filter((address) => !mapped.has(address))
      .map((address) => name(rightByAddress, address))
      .slice(0, LIST_LIMIT),
    calls_removed: left.callees
      .filter(
        (address) => !rightCallees.has(partner.get(address)?.address ?? ""),
      )
      .map((address) => name(leftByAddress, address))
      .slice(0, LIST_LIMIT),
    strings_added: difference(right.strings, left.strings),
    strings_removed: difference(left.strings, right.strings),
    constants_added: difference(right.constants, left.constants),
    constants_removed: difference(left.constants, right.constants),
  };
};

const unmatchedRow = (
  item: FunctionFeatures,
  status: "removed" | "added",
): DiffUnmatchedRow => ({
  status,
  address: item.address,
  name: item.name,
  instructions: item.normalized.length,
  blocks: item.blocks,
  calls: item.calleeNames.slice(0, LIST_LIMIT),
  strings: item.strings.slice(0, LIST_LIMIT),
});

const listed = (item: FunctionFeatures, at: number) =>
  `${item.lineAddresses[at] ?? ""}: ${item.lines[at] ?? ""}`;

/** The aligned instruction listing of a pair, or one side's listing alone. */
export const listing = (
  left: FunctionFeatures | undefined,
  right: FunctionFeatures | undefined,
): { rows: DiffListingRow[]; truncated: boolean } => {
  if (left === undefined || right === undefined) {
    const only = (left ?? right) as FunctionFeatures;
    const change = left === undefined ? "added" : "removed";
    const rows = only.lines.map((_, at) => ({
      change,
      left: left === undefined ? null : listed(only, at),
      right: left === undefined ? listed(only, at) : null,
    })) satisfies DiffListingRow[];
    return {
      rows: rows.slice(0, DIFF_LISTING_LIMIT),
      truncated: rows.length > DIFF_LISTING_LIMIT,
    };
  }
  const edits = editScript(left.normalized, right.normalized);
  if (edits === null) return { rows: [], truncated: true };
  const rows: DiffListingRow[] = [];
  let x = 0;
  let y = 0;
  for (const edit of edits) {
    rows.push({
      change: edit,
      left: edit === "added" ? null : listed(left, x),
      right: edit === "removed" ? null : listed(right, y),
    });
    if (edit !== "added") x += 1;
    if (edit !== "removed") y += 1;
  }
  return {
    rows: rows.slice(0, DIFF_LISTING_LIMIT),
    truncated: rows.length > DIFF_LISTING_LIMIT,
  };
};

const buildFacts = (inventory: FunctionInventory) => ({
  path: inventory.path,
  sha256: inventory.sha256,
  format: inventory.format,
  analysis_provider: inventory.provider.id,
  analysis_profile: inventory.profile?.digest ?? null,
  functions_listed: inventory.listed,
  functions_analyzed: inventory.functions.length,
  functions_failed: inventory.failed.length,
  truncated: inventory.truncated,
});

const numeric = (address: string) => BigInt(address);
const byAddress = (left: string, right: string) => {
  const a = numeric(left);
  const b = numeric(right);
  return a < b ? -1 : a > b ? 1 : 0;
};

/** Everything a page is cut from: all rows of every view. */
export interface DiffTables {
  readonly pairs: readonly DiffPairRow[];
  readonly unmatched: readonly DiffUnmatchedRow[];
  readonly matches: readonly FunctionMatch[];
  readonly removed: readonly FunctionFeatures[];
  readonly added: readonly FunctionFeatures[];
  readonly similarityComplete: boolean;
}

export const diffTables = (
  left: FunctionInventory,
  right: FunctionInventory,
  result: ReturnType<typeof matchFunctions>,
): DiffTables => {
  const leftByAddress = new Map(
    left.functions.map((item) => [item.address, item]),
  );
  const rightByAddress = new Map(
    right.functions.map((item) => [item.address, item]),
  );
  const partner = new Map(
    result.matches.map(({ left: a, right: b }) => [a.address, b]),
  );
  const matches = [...result.matches].sort((a, b) =>
    byAddress(a.left.address, b.left.address),
  );
  return {
    pairs: matches.map((match) =>
      pairRow(match, partner, leftByAddress, rightByAddress),
    ),
    unmatched: [
      ...[...result.removed]
        .sort((a, b) => byAddress(a.address, b.address))
        .map((item) => unmatchedRow(item, "removed")),
      ...[...result.added]
        .sort((a, b) => byAddress(a.address, b.address))
        .map((item) => unmatchedRow(item, "added")),
    ],
    matches,
    removed: result.removed,
    added: result.added,
    similarityComplete: result.similarityComplete,
  };
};

const matchesQuery = (query: string | undefined, ...texts: string[]) =>
  query === undefined ||
  texts.some((text) => text.toLowerCase().includes(query.toLowerCase()));

/** The page of one view. */
export const diffReport = (
  left: FunctionInventory,
  right: FunctionInventory,
  tables: DiffTables,
  input: DiffBinariesInput,
): BinaryDiffReport => {
  const { pairs, unmatched } = tables;
  const changed = pairs.filter(({ status }) => status === "changed");
  const byMethod = Object.fromEntries(
    DIFF_METHODS.map((method) => [
      method,
      pairs.filter((pair) => pair.method === method).length,
    ]),
  ) as Record<(typeof DIFF_METHODS)[number], number>;
  let functions: DiffPairRow[] = [];
  let rest: DiffUnmatchedRow[] = [];
  let listingRows: DiffListingRow[] = [];
  let listingTruncated = false;
  const pairQuery = (pair: DiffPairRow) =>
    matchesQuery(
      input.query,
      pair.left.address,
      pair.left.name,
      pair.right.address,
      pair.right.name,
    );
  if (input.view === "summary")
    functions = [...changed]
      .filter(pairQuery)
      .sort((a, b) => a.similarity - b.similarity);
  else if (input.view === "functions")
    functions = pairs.filter(
      (pair) =>
        (input.status === undefined || pair.status === input.status) &&
        pairQuery(pair),
    );
  else if (input.view === "unmatched")
    rest = unmatched.filter(
      (row) =>
        (input.status === undefined || row.status === input.status) &&
        matchesQuery(input.query, row.address, row.name),
    );
  else {
    const selected = selectFunction(tables, input.function ?? "");
    if (selected.pair !== undefined) functions = [selected.pair];
    if (selected.unmatched !== undefined) rest = [selected.unmatched];
    if (selected.left !== undefined || selected.right !== undefined) {
      const shown = listing(selected.left, selected.right);
      listingRows = shown.rows;
      listingTruncated = shown.truncated;
    }
  }
  const rows = input.view === "unmatched" ? rest : functions;
  const total =
    input.view === "function" ? functions.length + rest.length : rows.length;
  const page = <Row>(items: Row[]) =>
    input.view === "function"
      ? items
      : items.slice(input.offset, input.offset + input.limit);
  const pagedFunctions = page(functions);
  const pagedRest = page(rest);
  return {
    left: buildFacts(left),
    right: buildFacts(right),
    summary: {
      matched: pairs.length,
      identical: pairs.length - changed.length,
      changed: changed.length,
      removed: tables.removed.length,
      added: tables.added.length,
      by_method: byMethod,
      similarity_complete: tables.similarityComplete,
    },
    page: {
      view: input.view,
      status: input.status ?? null,
      function: input.function ?? null,
      query: input.query ?? null,
      offset: input.view === "function" ? 0 : input.offset,
      limit: input.limit,
      total,
      returned: pagedFunctions.length + pagedRest.length,
    },
    functions: pagedFunctions,
    unmatched: pagedRest,
    listing: listingRows,
    listing_truncated: listingTruncated,
  };
};

interface Selection {
  readonly pair?: DiffPairRow | undefined;
  readonly unmatched?: DiffUnmatchedRow | undefined;
  readonly left?: FunctionFeatures;
  readonly right?: FunctionFeatures;
}

/** A function by address or name: the left build first, then the right. */
const selectFunction = (tables: DiffTables, selector: string): Selection => {
  const wanted = selector.toLowerCase();
  const hits = (item: FunctionFeatures) =>
    item.address === wanted || item.name.toLowerCase() === wanted;
  for (const side of ["left", "right"] as const) {
    const index = tables.matches.findIndex((match) => hits(match[side]));
    const match = tables.matches[index];
    if (match !== undefined)
      return {
        pair: tables.pairs.find(
          (pair) => pair.left.address === match.left.address,
        ),
        left: match.left,
        right: match.right,
      };
    const lone = (side === "left" ? tables.removed : tables.added).find(hits);
    if (lone !== undefined)
      return {
        unmatched: tables.unmatched.find(
          (row) =>
            row.address === lone.address &&
            row.status === (side === "left" ? "removed" : "added"),
        ),
        ...(side === "left" ? { left: lone } : { right: lone }),
      };
  }
  return {};
};
