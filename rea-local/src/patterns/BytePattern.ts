/** A pattern that is empty, too long, malformed or entirely wildcards. */
export class BytePatternError extends Error {}

export const MAX_PATTERN_BYTES = 256;

/** Per-byte value and mask; mask 0xff is fixed, 0x00 a full wildcard. */
export interface BytePattern {
  readonly values: Uint8Array;
  readonly masks: Uint8Array;
  /** Canonical spaced form, upper-case, `??` for full wildcards. */
  readonly text: string;
  /** Longest run of fully fixed bytes, used as the search anchor. */
  readonly anchor: { readonly offset: number; readonly bytes: Buffer };
  /** Starts of runs of exactly four full wildcards (rel32 candidates). */
  readonly displacements: readonly number[];
}

const nibble = (character: string): { value: number; mask: number } =>
  character === "?"
    ? { value: 0, mask: 0 }
    : /^[0-9a-f]$/iu.test(character)
      ? { value: Number.parseInt(character, 16), mask: 0xf }
      : (() => {
          throw new BytePatternError(
            `Invalid pattern character "${character}".`,
          );
        })();

/**
 * Parse Cheat Engine / IDA style patterns: `48 8B 05 ?? ?? ?? ??`, single `?`
 * byte wildcards, nibble wildcards such as `4?`, or unspaced `488B05????`.
 */
export const parseBytePattern = (source: string): BytePattern => {
  const trimmed = source.trim();
  const tokens = /\s/u.test(trimmed)
    ? trimmed.split(/\s+/u)
    : trimmed.length % 2 === 0
      ? (trimmed.match(/.{2}/gu) ?? [])
      : [];
  if (tokens.length === 0 || tokens.length > MAX_PATTERN_BYTES)
    throw new BytePatternError(
      `Expected 1-${String(MAX_PATTERN_BYTES)} space-separated bytes, got "${source.slice(0, 80)}".`,
    );
  const values = new Uint8Array(tokens.length);
  const masks = new Uint8Array(tokens.length);
  tokens.forEach((token, index) => {
    const pair = token === "?" ? "??" : token;
    if (pair.length !== 2)
      throw new BytePatternError(`Invalid pattern byte "${token}".`);
    const high = nibble(pair[0] ?? "");
    const low = nibble(pair[1] ?? "");
    values[index] = (high.value << 4) | low.value;
    masks[index] = (high.mask << 4) | low.mask;
  });
  let best = { offset: 0, length: 0 };
  let start = -1;
  masks.forEach((mask, index) => {
    if (mask === 0xff) {
      if (start < 0) start = index;
      if (index - start + 1 > best.length)
        best = { offset: start, length: index - start + 1 };
    } else start = -1;
  });
  if (best.length === 0)
    throw new BytePatternError(
      "A pattern needs at least one fully fixed byte.",
    );
  const displacements: number[] = [];
  for (let index = 0; index + 4 <= masks.length; index += 1) {
    const run = [0, 1, 2, 3].every((step) => masks[index + step] === 0);
    const before = index === 0 || masks[index - 1] !== 0;
    const after = index + 4 === masks.length || masks[index + 4] !== 0;
    if (run && before && after) displacements.push(index);
  }
  return {
    values,
    masks,
    text: Array.from(values, (value, index) => {
      const mask = masks[index] ?? 0;
      const digits = value.toString(16).toUpperCase().padStart(2, "0");
      return [0xf0, 0x0f].reduce(
        (shown, part, position) =>
          (mask & part) === 0
            ? `${shown.slice(0, position)}?${shown.slice(position + 1)}`
            : shown,
        digits,
      );
    }).join(" "),
    anchor: {
      offset: best.offset,
      bytes: Buffer.from(
        values.subarray(best.offset, best.offset + best.length),
      ),
    },
    displacements,
  };
};

/** Whether the pattern matches at `offset`. */
const matchesAt = (
  bytes: Buffer,
  pattern: BytePattern,
  offset: number,
): boolean => {
  if (offset < 0 || offset + pattern.values.length > bytes.length) return false;
  for (let index = 0; index < pattern.values.length; index += 1)
    if (
      ((bytes[offset + index] ?? 0) & (pattern.masks[index] ?? 0)) !==
      (pattern.values[index] ?? 0)
    )
      return false;
  return true;
};

/**
 * File offsets where the pattern matches inside [start, end), anchored on its
 * longest fixed run. Counting stops at `countLimit`.
 */
export const scanBytes = (
  bytes: Buffer,
  pattern: BytePattern,
  range: { readonly start: number; readonly end: number },
  countLimit: number,
): { readonly offsets: number[]; readonly complete: boolean } => {
  const offsets: number[] = [];
  const { offset: anchorOffset, bytes: anchor } = pattern.anchor;
  let from = range.start + anchorOffset;
  while (offsets.length < countLimit) {
    const found = bytes.indexOf(anchor, from);
    if (found < 0) return { offsets, complete: true };
    const start = found - anchorOffset;
    if (start + pattern.values.length > range.end)
      return { offsets, complete: true };
    if (start >= range.start && matchesAt(bytes, pattern, start))
      offsets.push(start);
    from = found + 1;
  }
  return { offsets, complete: false };
};
