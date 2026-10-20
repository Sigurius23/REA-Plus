/**
 * drcov 3 logs in DynamoRIO 11.2's Linux layout (module table version 5),
 * built in source so tests need no tracer.
 */
export interface DrcovFixtureModule {
  readonly path: string;
  /** Segment start, end and preferred base, in module order. */
  readonly segments: readonly (readonly [
    start: bigint,
    end: bigint,
    preferred: bigint,
  ])[];
}

/** Block start (relative to its segment), size and segment row. */
export type DrcovFixtureBlock = readonly [
  start: number,
  size: number,
  segment: number,
];

const hex16 = (value: bigint) => value.toString(16).padStart(16, "0");

export const createDrcovLog = (
  modules: readonly DrcovFixtureModule[],
  blocks: readonly DrcovFixtureBlock[],
): Buffer => {
  const rows: string[] = [];
  for (const module of modules) {
    const containing = rows.length;
    for (const [start, end, preferred] of module.segments)
      rows.push(
        `${String(rows.length).padStart(3)}, ${String(containing).padStart(3)}, 0x${hex16(start)}, 0x${hex16(end)}, 0x${hex16(start)}, ${hex16(start - (module.segments[0]?.[0] ?? start))}, 0x${hex16(preferred)},  ${module.path}`,
      );
  }
  const header = Buffer.from(
    `DRCOV VERSION: 3\nDRCOV FLAVOR: drcov-64\nModule Table: version 5, count ${String(rows.length)}\nColumns: id, containing_id, start, end, entry, offset, preferred_base, path\n${rows.join("\n")}\nBB Table: ${String(blocks.length)} bbs\n`,
  );
  const table = Buffer.alloc(blocks.length * 8);
  blocks.forEach(([start, size, segment], index) => {
    table.writeUInt32LE(start, index * 8);
    table.writeUInt16LE(size, index * 8 + 4);
    table.writeUInt16LE(segment, index * 8 + 6);
  });
  return Buffer.concat([header, table]);
};
