import type {
  BytePatternScan,
  PatternResult,
} from "../domain/patterns/bytePatterns.js";
import {
  parseBytePattern,
  scanBytes,
  type BytePattern,
} from "./BytePattern.js";
import {
  readImageLayout,
  sectionAtAddress,
  sectionAtOffset,
  type ImageLayout,
  type ImageSection,
} from "./ImageLayout.js";

/** Matches counted per pattern before reporting an incomplete total. */
const COUNT_LIMIT = 100_000;

const hex = (value: bigint): string => `0x${value.toString(16)}`;

export interface ScanRegion {
  readonly name: string;
  readonly start: number;
  readonly end: number;
}

/** Regions to scan for a scope; unmapped files scan whole. */
export const scanRegions = (
  layout: ImageLayout,
  bytes: Buffer,
  scope: "executable" | "all",
): {
  readonly scope: "executable" | "all" | "file";
  readonly regions: ScanRegion[];
} => {
  const chosen = layout.sections.filter(
    ({ executable }) => scope === "all" || executable,
  );
  if (chosen.length === 0)
    return {
      scope: "file",
      regions: [{ name: "<file>", start: 0, end: bytes.length }],
    };
  return {
    scope,
    regions: chosen.map(({ name, fileOffset, size }) => ({
      name,
      start: fileOffset,
      end: Math.min(bytes.length, fileOffset + size),
    })),
  };
};

const addressOf = (section: ImageSection | undefined, offset: number) =>
  section === undefined
    ? null
    : section.address + BigInt(offset - section.fileOffset);

/** Resolve each four-wildcard run as rel32 from the end of the run. */
const displacements = (
  { bytes, layout }: { readonly bytes: Buffer; readonly layout: ImageLayout },
  pattern: BytePattern,
  offset: number,
  section: ImageSection | undefined,
) =>
  pattern.displacements.map((at) => {
    const value = bytes.readInt32LE(offset + at);
    const next = addressOf(section, offset + at + 4);
    const target = next === null ? null : next + BigInt(value);
    return {
      pattern_offset: at,
      value,
      target: target === null || target < 0n ? null : hex(target),
      target_section:
        target === null
          ? null
          : (sectionAtAddress(layout, target)?.name ?? null),
    };
  });

/** Scan every pattern over the chosen regions. */
export const scanPatterns = (
  bytes: Buffer,
  layout: ImageLayout,
  patterns: readonly {
    readonly name?: string | undefined;
    readonly pattern: string;
  }[],
  options: {
    readonly scope: "executable" | "all";
    readonly maxMatches: number;
  },
): Pick<BytePatternScan, "scanned" | "results"> => {
  const { scope, regions } = scanRegions(layout, bytes, options.scope);
  const results = patterns.map(({ name, pattern: source }): PatternResult => {
    const pattern = parseBytePattern(source);
    const offsets = new Set<number>();
    let complete = true;
    for (const region of regions) {
      const found = scanBytes(
        bytes,
        pattern,
        region,
        COUNT_LIMIT - offsets.size,
      );
      for (const offset of found.offsets) offsets.add(offset);
      if (!found.complete) {
        complete = false;
        break;
      }
    }
    const sorted = [...offsets].sort((left, right) => left - right);
    return {
      name: name ?? null,
      pattern: pattern.text,
      length: pattern.values.length,
      total_matches: sorted.length,
      complete,
      matches: sorted.slice(0, options.maxMatches).map((offset) => {
        const section = sectionAtOffset(layout, offset);
        const address = addressOf(section, offset);
        return {
          file_offset: offset,
          address: address === null ? null : hex(address),
          rva:
            address === null || layout.imageBase === null
              ? null
              : hex(address - layout.imageBase),
          section: section?.name ?? null,
          bytes: bytes
            .subarray(offset, offset + pattern.values.length)
            .toString("hex"),
          displacements: displacements(
            { bytes, layout },
            pattern,
            offset,
            section,
          ),
        };
      }),
    };
  });
  return {
    scanned: {
      scope,
      regions: regions.map(({ name }) => name),
      bytes: regions.reduce((total, { start, end }) => total + end - start, 0),
    },
    results,
  };
};

export const layoutRecord = (
  layout: ImageLayout,
): Omit<
  BytePatternScan["file"],
  "path" | "sha256" | "bytes" | "layout_error"
> => ({
  format: layout.format,
  architecture: layout.architecture,
  image_base: layout.imageBase === null ? null : hex(layout.imageBase),
  sections: layout.sections.map((section) => ({
    name: section.name,
    file_offset: section.fileOffset,
    size: section.size,
    address: hex(section.address),
    executable: section.executable,
  })),
});

export { readImageLayout };
