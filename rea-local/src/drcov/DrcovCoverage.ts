import type {
  CoverageBlock,
  CoverageModule,
} from "../domain/drcov/coverageLog.js";
import type { DrcovLog, DrcovSegment } from "./DrcovLog.js";

const hex = (value: bigint | number): string => `0x${value.toString(16)}`;

/** One mapped module: the segments sharing a containing module row. */
export interface DrcovModule {
  readonly path: string;
  readonly segments: readonly DrcovSegment[];
  readonly runtimeBase: bigint;
  readonly runtimeEnd: bigint;
  /** Unique blocks by image offset and size, in image-offset order. */
  readonly blocks: readonly (CoverageBlock & { readonly offset: number })[];
  /** Merged covered [start, end) image-offset ranges. */
  readonly ranges: readonly (readonly [number, number])[];
}

const mergeRanges = (
  blocks: readonly { readonly offset: number; readonly size: number }[],
) => {
  const ranges: [number, number][] = [];
  for (const { offset, size } of blocks) {
    if (size === 0) continue;
    const last = ranges.at(-1);
    if (last !== undefined && offset <= last[1])
      last[1] = Math.max(last[1], offset + size);
    else ranges.push([offset, offset + size]);
  }
  return ranges;
};

/** Group segments into modules and collect each module's unique blocks. */
export const drcovModules = (log: DrcovLog): DrcovModule[] => {
  const owners = new Map<number, DrcovSegment[]>();
  for (const segment of log.segments)
    owners.set(segment.containingId, [
      ...(owners.get(segment.containingId) ?? []),
      segment,
    ]);
  const baseOf = new Map<number, bigint>();
  for (const [owner, segments] of owners)
    baseOf.set(
      owner,
      segments.reduce(
        (lowest, { start }) => (start < lowest ? start : lowest),
        segments[0]?.start ?? 0n,
      ),
    );
  const blocks = new Map<
    number,
    Map<string, CoverageBlock & { offset: number }>
  >();
  for (let index = 0; index < log.blockStarts.length; index += 1) {
    const segment = log.segments[log.blockSegments[index] ?? 0];
    if (segment === undefined) continue;
    const start = BigInt(log.blockStarts[index] ?? 0);
    const size = log.blockSizes[index] ?? 0;
    const image =
      segment.start -
      (baseOf.get(segment.containingId) ?? segment.start) +
      start;
    const key = `${image.toString(16)}:${String(size)}`;
    const unique = blocks.get(segment.containingId) ?? new Map();
    blocks.set(segment.containingId, unique);
    if (!unique.has(key))
      unique.set(key, {
        offset: Number(image),
        image_offset: hex(image),
        static_address:
          segment.preferredBase === null
            ? null
            : hex(segment.preferredBase + start),
        runtime_address: hex(segment.start + start),
        size,
        segment_id: segment.id,
      });
  }
  return [...owners].map(([owner, segments]) => {
    const unique = [...(blocks.get(owner)?.values() ?? [])].sort(
      (left, right) => left.offset - right.offset || left.size - right.size,
    );
    return {
      path: segments[0]?.path ?? "",
      segments,
      runtimeBase: baseOf.get(owner) ?? 0n,
      runtimeEnd: segments.reduce(
        (highest, { end }) => (end > highest ? end : highest),
        0n,
      ),
      blocks: unique,
      ranges: mergeRanges(unique),
    };
  });
};

const coveredBytes = (ranges: readonly (readonly [number, number])[]) =>
  ranges.reduce((total, [start, end]) => total + end - start, 0);

/** Baseline coverage by module path, merged across same-path modules. */
export const baselineRanges = (
  modules: readonly DrcovModule[],
): Map<string, (readonly [number, number])[]> => {
  const byPath = new Map<string, { offset: number; size: number }[]>();
  for (const module of modules)
    byPath.set(module.path, [
      ...(byPath.get(module.path) ?? []),
      ...module.blocks,
    ]);
  return new Map(
    [...byPath].map(([path, blocks]) => [
      path,
      mergeRanges(
        [...blocks].sort((left, right) => left.offset - right.offset),
      ),
    ]),
  );
};

/** True when [offset, offset + size) lies inside one merged range. */
const covered = (
  ranges: readonly (readonly [number, number])[],
  offset: number,
  size: number,
): boolean => {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const [start, end] = ranges[middle] ?? [0, 0];
    if (offset < start) high = middle - 1;
    else if (offset >= end) low = middle + 1;
    else return offset + Math.max(size, 1) <= end;
  }
  return false;
};

/** Blocks with bytes the baseline did not execute, in image-offset order. */
export const newBlocks = (
  module: DrcovModule,
  baseline: ReadonlyMap<string, readonly (readonly [number, number])[]> | null,
): readonly (CoverageBlock & { readonly offset: number })[] => {
  if (baseline === null) return module.blocks;
  const ranges = baseline.get(module.path) ?? [];
  return module.blocks.filter(
    ({ offset, size }) => !covered(ranges, offset, size),
  );
};

/** Per-module summary rows for modules with at least one block. */
export const summarizeModules = (
  modules: readonly DrcovModule[],
  baseline: ReadonlyMap<string, readonly (readonly [number, number])[]> | null,
): CoverageModule[] =>
  modules
    .filter(({ blocks }) => blocks.length > 0)
    .map((module) => ({
      path: module.path,
      segments: module.segments.length,
      runtime_base: hex(module.runtimeBase),
      runtime_end: hex(module.runtimeEnd),
      unique_blocks: module.blocks.length,
      covered_bytes: coveredBytes(module.ranges),
      new_blocks: baseline === null ? null : newBlocks(module, baseline).length,
      baseline_covered_bytes:
        baseline === null
          ? null
          : coveredBytes(baseline.get(module.path) ?? []),
    }))
    .sort(
      (left, right) =>
        right.unique_blocks - left.unique_blocks ||
        left.path.localeCompare(right.path),
    );

/** Hex rendering shared with the report. */
export const toHex = hex;
