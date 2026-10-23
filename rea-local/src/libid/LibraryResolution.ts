import { bytesAt, type TargetImage } from "./TargetImage.js";
import type { Hit, Signature } from "./LibrarySignatures.js";
import type { ObjectReference } from "./ObjectFiles.js";
import { compositeKey } from "../domain/unicodeCodePointOrder.js";

/**
 * Turn raw signature hits into identified functions. A hit inside a longer
 * hit is dropped, and names for the same code (aliases) are one function.
 * Signatures with the same bytes but different code (a thunk to adler32_z
 * and one to crc32_z, or gztell and gztell64) are told apart by:
 * - references: a call must land on a function identified under the
 *   referenced name, and a referenced string must be the same string;
 * - layout: functions of one object section keep their relative offsets, so
 *   an identified neighbour fixes where its siblings are.
 */

export type IdentificationStatus = "unique" | "resolved" | "ambiguous";

export interface Identified {
  readonly address: bigint;
  readonly length: number;
  readonly names: readonly string[];
  readonly signatures: readonly Signature[];
  readonly status: IdentificationStatus;
  readonly confirmed: number;
  readonly contradicted: number;
  readonly unchecked: number;
}

interface Group {
  readonly address: bigint;
  readonly candidates: Signature[];
  chosen: Signature[];
  status: IdentificationStatus;
}

const MAX_ROUNDS = 10;
const STRING_MIN = 4;

/** A NUL-terminated printable string at the start of the bytes, if any. */
const leadingString = (data: Buffer): Buffer | null => {
  const end = data.indexOf(0);
  if (end < STRING_MIN) return null;
  for (let at = 0; at < end; at += 1) {
    const byte = data[at] ?? 0;
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20) || byte > 0x7e) return null;
  }
  return data.subarray(0, end + 1);
};

type Verdict = "confirmed" | "contradicted" | "unchecked";

const verdict = (
  image: TargetImage,
  names: ReadonlyMap<bigint, ReadonlySet<string>>,
  at: bigint,
  reference: ObjectReference,
): Verdict => {
  const field = bytesAt(image, at + BigInt(reference.offset), 4);
  if (field === null || field.length < 4) return "unchecked";
  const target =
    at + BigInt(reference.offset) + 4n + BigInt(field.readInt32LE(0));
  if (reference.symbol !== null) {
    const there = names.get(target);
    if (there === undefined) return "unchecked";
    return there.has(reference.symbol) ? "confirmed" : "contradicted";
  }
  const expected =
    reference.data === null ? null : leadingString(reference.data);
  if (expected === null) return "unchecked";
  const actual = bytesAt(image, target, expected.length);
  if (actual === null) return "contradicted";
  return actual.equals(expected) ? "confirmed" : "contradicted";
};

const tally = (
  image: TargetImage,
  names: ReadonlyMap<bigint, ReadonlySet<string>>,
  at: bigint,
  signature: Signature,
) => {
  const counts = { confirmed: 0, contradicted: 0, unchecked: 0 };
  for (const reference of signature.references)
    counts[verdict(image, names, at, reference)] += 1;
  return counts;
};

const origin = (signature: Signature) =>
  compositeKey([signature.section, signature.offset]);

/** Drop hits that start inside a longer hit at another address. */
const outermost = (hits: readonly Hit[]): Group[] => {
  const byAddress = new Map<bigint, Signature[]>();
  for (const { address, signature } of hits)
    byAddress.set(address, [...(byAddress.get(address) ?? []), signature]);
  const groups = [...byAddress]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([address, candidates]) => ({
      address,
      candidates,
      length: Math.max(...candidates.map(({ bytes }) => bytes.length)),
    }));
  const kept: Group[] = [];
  let end = -1n;
  let outerLength = 0;
  for (const group of groups) {
    const groupEnd = group.address + BigInt(group.length);
    if (group.address < end && groupEnd <= end && group.length < outerLength)
      continue;
    if (groupEnd > end) {
      end = groupEnd;
      outerLength = group.length;
    }
    const distinct = new Set(group.candidates.map(origin));
    kept.push({
      address: group.address,
      candidates: group.candidates,
      chosen: group.candidates,
      status: distinct.size === 1 ? "unique" : "ambiguous",
    });
  }
  return kept;
};

const nameMap = (groups: readonly Group[]) =>
  new Map(
    groups
      .filter(({ status }) => status !== "ambiguous")
      .map(({ address, chosen }) => [
        address,
        new Set(chosen.map(({ name }) => name)),
      ]),
  );

/** Identified functions per object section, to check a candidate's offset against. */
const layoutMap = (groups: readonly Group[]) => {
  const placed = new Map<string, { address: bigint; offset: number }[]>();
  for (const { status, chosen, address } of groups) {
    const [first] = chosen;
    if (status === "ambiguous" || first === undefined) continue;
    placed.set(first.section, [
      ...(placed.get(first.section) ?? []),
      { address, offset: first.offset },
    ]);
  }
  return placed;
};

const laidOut = (
  placed: ReturnType<typeof layoutMap>,
  address: bigint,
  signature: Signature,
) =>
  (placed.get(signature.section) ?? []).some(
    (neighbour) =>
      address - neighbour.address ===
      BigInt(signature.offset - neighbour.offset),
  );

/** Identify functions from hits, settling same-byte collisions by references and layout. */
export const resolveHits = (
  image: TargetImage,
  hits: readonly Hit[],
): Identified[] => {
  const groups = outermost(hits);
  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const names = nameMap(groups);
    const placed = layoutMap(groups);
    let changed = false;
    for (const group of groups) {
      if (group.status !== "ambiguous") continue;
      const scored = group.candidates.map((signature) => {
        const counts = tally(image, names, group.address, signature);
        return {
          signature,
          score:
            counts.confirmed -
            2 * counts.contradicted +
            (laidOut(placed, group.address, signature) ? 3 : 0),
        };
      });
      const best = Math.max(...scored.map(({ score }) => score));
      const winners = scored.filter(({ score }) => score === best);
      const winnerOrigins = new Set(
        winners.map(({ signature }) => origin(signature)),
      );
      if (winnerOrigins.size === 1 && winners.length < scored.length) {
        group.chosen = winners.map(({ signature }) => signature);
        group.status = "resolved";
        changed = true;
      }
    }
    if (!changed) break;
  }
  const names = nameMap(groups);
  return groups.map((group) => {
    const [first] = group.chosen;
    const counts =
      first === undefined
        ? { confirmed: 0, contradicted: 0, unchecked: 0 }
        : tally(image, names, group.address, first);
    return {
      address: group.address,
      length: Math.max(...group.chosen.map(({ bytes }) => bytes.length)),
      names: [...new Set(group.chosen.map(({ name }) => name))].sort(),
      signatures: group.chosen,
      status: group.status,
      ...counts,
    };
  });
};
