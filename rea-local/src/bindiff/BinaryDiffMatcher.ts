import type { DIFF_METHODS } from "../domain/bindiff/binaryDiff.js";
import { editScript } from "./BinaryDiffEdits.js";
import type { FunctionFeatures } from "./BinaryDiffFeatures.js";

/**
 * Function matching between two builds, after BinDiff and Diaphora: unique
 * keys first (names, identical instructions, identical mnemonics, shared
 * strings and constants with the same shape), then neighbours of matched
 * pairs in the call graph, then the most similar remaining pairs. Every pass
 * matches only pairs that are each other's single best candidate.
 */

export type MatchMethod = (typeof DIFF_METHODS)[number];

export interface FunctionMatch {
  readonly left: FunctionFeatures;
  readonly right: FunctionFeatures;
  readonly method: MatchMethod;
  readonly similarity: number;
  /**
   * Share of matched callers and callees that correspond when the pair was
   * made; null when neither side had a matched neighbour.
   */
  readonly agreement: number | null;
}

export interface MatchOptions {
  /** Match functions with the same non-generated name first. */
  readonly names: boolean;
  /** Lowest similarity a call-graph or similarity match may have. */
  readonly threshold: number;
}

/** Fewer instructions than this rarely identify a function on their own. */
const MIN_UNIQUE_INSTRUCTIONS = 6;
/** Global similarity compares at most this many pairs. */
const MAX_SIMILARITY_PAIRS = 4_000_000;

const jaccard = (left: readonly string[], right: readonly string[]) => {
  if (left.length === 0 && right.length === 0) return undefined;
  const set = new Set(left);
  const shared = right.filter((item) => set.has(item)).length;
  return shared / (left.length + right.length - shared);
};

/** Multiset overlap of two token lists. */
const bigrams = (items: readonly string[]) =>
  items.slice(1).map((item, at) => `${items[at] ?? ""}|${item}`);

interface Counted {
  readonly counts: ReadonlyMap<string, number>;
  readonly size: number;
}

const counted = (items: readonly string[]): Counted => {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(item, (counts.get(item) ?? 0) + 1);
  return { counts, size: items.length };
};

/** Token counts per function, built once: the similarity pass compares many pairs. */
const prepared = new WeakMap<
  FunctionFeatures,
  { normalized: Counted; bigrams: Counted; mnemonics: Counted }
>();
const prepare = (item: FunctionFeatures) => {
  let value = prepared.get(item);
  if (value === undefined) {
    value = {
      normalized: counted(item.normalized),
      bigrams: counted(bigrams(item.mnemonics)),
      mnemonics: counted(item.mnemonics),
    };
    prepared.set(item, value);
  }
  return value;
};

/** Multiset overlap (Dice) of two token lists. */
const overlap = (left: Counted, right: Counted) => {
  if (left.size === 0 && right.size === 0) return undefined;
  const [small, large] =
    left.counts.size <= right.counts.size ? [left, right] : [right, left];
  let shared = 0;
  for (const [item, times] of small.counts)
    shared += Math.min(times, large.counts.get(item) ?? 0);
  return (2 * shared) / (left.size + right.size);
};

const closeness = (left: number, right: number) =>
  left === right ? 1 : Math.min(left, right) / Math.max(left, right);

/** Share of the smaller body's instructions that the other body also has. */
export const containment = (
  left: FunctionFeatures,
  right: FunctionFeatures,
): number => {
  const a = prepare(left).normalized;
  const b = prepare(right).normalized;
  const smaller = Math.min(a.size, b.size);
  return smaller === 0
    ? 0
    : ((overlap(a, b) ?? 0) * (a.size + b.size)) / 2 / smaller;
};

/** Weighted similarity in [0, 1]; features absent on both sides do not count. */
export const similarity = (
  left: FunctionFeatures,
  right: FunctionFeatures,
): number => {
  if (left.exactHash === right.exactHash) return 1;
  const a = prepare(left);
  const b = prepare(right);
  const parts: [number | undefined, number][] = [
    [overlap(a.normalized, b.normalized), 3],
    [overlap(a.bigrams, b.bigrams), 2],
    [overlap(a.mnemonics, b.mnemonics), 1],
    [closeness(left.blocks, right.blocks), 1],
    [closeness(left.edges + 1, right.edges + 1), 1],
    [left.shapeHash === right.shapeHash ? 1 : 0, 0.5],
    [closeness(left.size + 1, right.size + 1), 0.5],
    [jaccard(left.strings, right.strings), 2],
    [jaccard(left.constants, right.constants), 1.5],
    [jaccard(left.calleeNames, right.calleeNames), 1.5],
    [jaccard(left.names, right.names), 1],
    [closeness(left.callees.length + 1, right.callees.length + 1), 0.5],
  ];
  let total = 0;
  let weights = 0;
  for (const [value, weight] of parts)
    if (value !== undefined) {
      total += value * weight;
      weights += weight;
    }
  return weights === 0 ? 0 : Math.min(0.999, total / weights);
};

class Matching {
  readonly matches: FunctionMatch[] = [];
  readonly #left = new Map<string, FunctionFeatures>();
  readonly #right = new Map<string, FunctionFeatures>();
  readonly #pairs = new Map<string, string>();
  readonly #reverse = new Map<string, string>();

  constructor(
    left: readonly FunctionFeatures[],
    right: readonly FunctionFeatures[],
  ) {
    for (const item of left) this.#left.set(item.address, item);
    for (const item of right) this.#right.set(item.address, item);
  }

  unmatchedLeft(): FunctionFeatures[] {
    return [...this.#left.values()].filter(
      ({ address }) => !this.#pairs.has(address),
    );
  }

  unmatchedRight(): FunctionFeatures[] {
    return [...this.#right.values()].filter(
      ({ address }) => !this.#reverse.has(address),
    );
  }

  partner(address: string): string | undefined {
    return this.#pairs.get(address);
  }

  leftAt(address: string) {
    return this.#left.get(address);
  }

  rightAt(address: string) {
    return this.#right.get(address);
  }

  add(left: FunctionFeatures, right: FunctionFeatures, method: MatchMethod) {
    this.#pairs.set(left.address, right.address);
    this.#reverse.set(right.address, left.address);
    this.matches.push({
      left,
      right,
      method,
      similarity: similarity(left, right),
      agreement: this.agreement(left, right),
    });
  }

  /** Match functions whose key is unique among the unmatched on both sides. */
  byKey(
    method: MatchMethod,
    key: (item: FunctionFeatures) => string | undefined,
  ): void {
    const group = (items: FunctionFeatures[]) => {
      const groups = new Map<string, FunctionFeatures[]>();
      for (const item of items) {
        const value = key(item);
        if (value !== undefined)
          groups.set(value, [...(groups.get(value) ?? []), item]);
      }
      return groups;
    };
    const left = group(this.unmatchedLeft());
    const right = group(this.unmatchedRight());
    for (const [value, [first, ...others]] of left) {
      const partners = right.get(value);
      if (
        first !== undefined &&
        others.length === 0 &&
        partners?.length === 1 &&
        partners[0] !== undefined
      )
        this.add(first, partners[0], method);
    }
  }

  /**
   * Share of a pair's matched callers and callees whose partners are the
   * other side's callers and callees: identical thunks to different targets
   * differ here.
   */
  agreement(left: FunctionFeatures, right: FunctionFeatures): number | null {
    const neighbours = new Set([...right.callees, ...right.callers]);
    const mapped = [...left.callees, ...left.callers]
      .map((address) => this.#pairs.get(address))
      .filter((address) => address !== undefined);
    const matchedRight = [...neighbours].filter((address) =>
      this.#reverse.has(address),
    ).length;
    const shared = mapped.filter((address) => neighbours.has(address)).length;
    const total = Math.max(mapped.length, matchedRight);
    return total === 0 ? null : shared / total;
  }

  /** Mutually best pairs above the threshold, best first. */
  bestPairs(
    method: MatchMethod,
    pairs: readonly (readonly [FunctionFeatures, FunctionFeatures])[],
    threshold: number,
  ): number {
    const distinct = new Map(
      pairs.map((pair) => [`${pair[0].address}|${pair[1].address}`, pair]),
    );
    // Rank by content, then by call-graph agreement.
    const scored = [...distinct.values()]
      .map(([left, right]) => ({
        left,
        right,
        similarity: similarity(left, right),
      }))
      .filter((pair) => pair.similarity >= threshold)
      .map((pair) => {
        const agreement = this.agreement(pair.left, pair.right);
        return {
          ...pair,
          agreement,
          score: pair.similarity + 0.25 * (agreement ?? 0),
        };
      })
      .filter((pair) => admitted(pair.similarity, pair.agreement, threshold));
    const bestLeft = new Map<string, number>();
    const bestRight = new Map<string, number>();
    const secondLeft = new Map<string, number>();
    const secondRight = new Map<string, number>();
    const note = (
      best: Map<string, number>,
      second: Map<string, number>,
      key: string,
      score: number,
    ) => {
      const current = best.get(key) ?? -1;
      if (score > current) {
        second.set(key, current);
        best.set(key, score);
      } else if (score > (second.get(key) ?? -1)) second.set(key, score);
    };
    for (const { left, right, score } of scored) {
      note(bestLeft, secondLeft, left.address, score);
      note(bestRight, secondRight, right.address, score);
    }
    let added = 0;
    for (const { left, right, score } of scored.sort(
      (a, b) => b.score - a.score,
    )) {
      if (
        this.#pairs.has(left.address) ||
        this.#reverse.has(right.address) ||
        score < (bestLeft.get(left.address) ?? 0) ||
        score < (bestRight.get(right.address) ?? 0) ||
        // A tie leaves the pair ambiguous.
        score === secondLeft.get(left.address) ||
        score === secondRight.get(right.address)
      )
        continue;
      this.add(left, right, method);
      added += 1;
    }
    return added;
  }

  /** Every pairing of unmatched neighbours on the left with those on the right. */
  #neighbourPairs(
    leftAddresses: readonly string[],
    rightAddresses: readonly string[],
  ): [FunctionFeatures, FunctionFeatures][] {
    const lefts = leftAddresses
      .filter((address) => !this.#pairs.has(address))
      .map((address) => this.#left.get(address))
      .filter((item) => item !== undefined);
    const rights = rightAddresses
      .filter((address) => !this.#reverse.has(address))
      .map((address) => this.#right.get(address))
      .filter((item) => item !== undefined);
    return lefts.flatMap((a) =>
      rights.map((b): [FunctionFeatures, FunctionFeatures] => [a, b]),
    );
  }

  /**
   * Unmatched callees at the same place in two matched callers' call
   * sequences, between calls that already correspond: a function changed in
   * place. Within such slots a pair must be each other's clear best by
   * containment, so a function added next to a changed one is no rival.
   */
  callOrder(threshold: number): number {
    const candidates = new Map<
      string,
      { left: FunctionFeatures; right: FunctionFeatures; value: number }
    >();
    for (const { left, right } of this.matches)
      for (const [a, b] of this.#slots(left.callSequence, right.callSequence))
        candidates.set(`${a.address}|${b.address}`, {
          left: a,
          right: b,
          value: containment(a, b),
        });
    const best = new Map<string, number[]>();
    const note = (key: string, value: number) =>
      best.set(
        key,
        [...(best.get(key) ?? []), value].sort((x, y) => y - x).slice(0, 2),
      );
    for (const { left, right, value } of candidates.values()) {
      note(`l${left.address}`, value);
      note(`r${right.address}`, value);
    }
    const clearBest = (key: string, value: number) => {
      const [first, second] = best.get(key) ?? [];
      return value === first && (second === undefined || second < value);
    };
    let added = 0;
    for (const { left, right, value } of candidates.values()) {
      if (
        value < 0.6 ||
        !clearBest(`l${left.address}`, value) ||
        !clearBest(`r${right.address}`, value) ||
        this.#pairs.has(left.address) ||
        this.#reverse.has(right.address) ||
        similarity(left, right) < threshold - 0.2
      )
        continue;
      this.add(left, right, "call-order");
      added += 1;
    }
    return added;
  }

  /** Pairings within gaps between corresponding calls, at most 4 unmatched callees a side. */
  #slots(
    leftCalls: readonly string[],
    rightCalls: readonly string[],
  ): [FunctionFeatures, FunctionFeatures][] {
    if (leftCalls.length === 0 || rightCalls.length === 0) return [];
    // Unmatched callees never align with anything.
    const mapped = leftCalls.map(
      (address, at) => this.#pairs.get(address) ?? `?${String(at)}`,
    );
    const edits = editScript(mapped, rightCalls, 500);
    if (edits === null) return [];
    const slots: [FunctionFeatures, FunctionFeatures][] = [];
    let lefts = new Set<string>();
    let rights = new Set<string>();
    const close = () => {
      if (lefts.size <= 4 && rights.size <= 4)
        slots.push(...this.#neighbourPairs([...lefts], [...rights]));
      lefts = new Set();
      rights = new Set();
    };
    let x = 0;
    let y = 0;
    for (const edit of edits) {
      if (edit === "same") close();
      if (edit === "removed") lefts.add(leftCalls[x] ?? "");
      if (edit === "added") rights.add(rightCalls[y] ?? "");
      if (edit !== "added") x += 1;
      if (edit !== "removed") y += 1;
    }
    close();
    return slots;
  }

  /** Callers and callees of matched pairs, until nothing more matches. */
  propagate(threshold: number): void {
    for (let added = 1; added > 0; ) {
      const pairs = this.matches.flatMap(({ left, right }) => [
        ...this.#neighbourPairs(left.callees, right.callees),
        ...this.#neighbourPairs(left.callers, right.callers),
      ]);
      added = this.bestPairs("call-graph", pairs, threshold);
    }
  }
}

/**
 * Changed functions are admitted on content and context together: neighbours
 * that mostly correspond allow less similar code, neighbours that disagree
 * rule a pair out, and a pair without matched neighbours needs close code.
 */
const admitted = (
  value: number,
  agreement: number | null,
  threshold: number,
): boolean => {
  if (agreement === null) return value >= Math.max(threshold, 0.8);
  if (agreement >= 0.75) return value >= threshold;
  if (agreement >= 0.5) return value >= threshold + 0.1;
  return false;
};

const longEnough = (item: FunctionFeatures) =>
  item.normalized.length >= MIN_UNIQUE_INSTRUCTIONS;

/** Match the functions of two builds. */
export const matchFunctions = (
  left: readonly FunctionFeatures[],
  right: readonly FunctionFeatures[],
  options: MatchOptions,
): {
  readonly matches: readonly FunctionMatch[];
  readonly removed: readonly FunctionFeatures[];
  readonly added: readonly FunctionFeatures[];
  readonly similarityComplete: boolean;
} => {
  const matching = new Matching(left, right);
  if (options.names)
    matching.byKey("name", (item) =>
      item.generatedName ? undefined : item.name,
    );
  matching.byKey("identical", (item) =>
    longEnough(item) ? item.exactHash : undefined,
  );
  matching.byKey("mnemonics", (item) =>
    longEnough(item) ? item.mnemonicHash : undefined,
  );
  matching.byKey("fingerprint", (item) =>
    item.strings.length + item.constants.length + item.calleeNames.length === 0
      ? undefined
      : JSON.stringify([
          item.shapeHash,
          item.strings,
          item.constants,
          item.calleeNames,
        ]),
  );
  const settle = () => {
    for (let added = 1; added > 0; ) {
      matching.propagate(options.threshold);
      added = matching.callOrder(options.threshold);
    }
  };
  settle();
  // Whatever remains: compare similar-sized functions, then propagate again.
  const lefts = matching.unmatchedLeft();
  const rights = matching.unmatchedRight();
  const pairs: [FunctionFeatures, FunctionFeatures][] = [];
  let compared = 0;
  for (const a of lefts)
    for (const b of rights) {
      if (closeness(a.normalized.length + 1, b.normalized.length + 1) < 0.5)
        continue;
      compared += 1;
      if (compared > MAX_SIMILARITY_PAIRS) break;
      pairs.push([a, b]);
    }
  matching.bestPairs("similarity", pairs, options.threshold);
  settle();
  return {
    matches: matching.matches,
    removed: matching.unmatchedLeft(),
    added: matching.unmatchedRight(),
    similarityComplete: compared <= MAX_SIMILARITY_PAIRS,
  };
};
