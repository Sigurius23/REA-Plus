import { describe, expect, it } from "vitest";

import {
  baselineRanges,
  drcovModules,
  newBlocks,
  summarizeModules,
} from "./DrcovCoverage.js";
import { DrcovFormatError, parseDrcovLog } from "./DrcovLog.js";

const LINUX_COLUMNS =
  "id, containing_id, start, end, entry, offset, preferred_base, path";

/** Rows recorded from DynamoRIO 11.2 drcov on Linux, with shortened paths. */
const LINUX_ROWS = [
  "  0,   0, 0x0000000000400000, 0x0000000000401000, 0x0000000000400100, 0000000000000000, 0x0000000000400000,  /work/branchy",
  "  1,   1, 0x00007f5e9cdf5000, 0x00007f5e9cdf7000, 0x00007f5e9cdf8010, 0000000000000000, 0x0000000000000000,  /usr/bin/echo",
  "  2,   1, 0x00007f5e9cdf7000, 0x00007f5e9cdfb000, 0x00007f5e9cdf8010, 0000000000002000, 0x0000000000002000,  /usr/bin/echo",
  " 3,   3, 0x00007f9b9c111000, 0x00007f9b9c113000, 0x00007f9b9c111000, 0000000000000000, 0x0000000000000000,  [vdso]",
];

type Block = readonly [start: number, size: number, segment: number];

const binaryTable = (blocks: readonly Block[]) =>
  Buffer.concat(
    blocks.map(([start, size, segment]) => {
      const entry = Buffer.alloc(8);
      entry.writeUInt32LE(start, 0);
      entry.writeUInt16LE(size, 4);
      entry.writeUInt16LE(segment, 6);
      return entry;
    }),
  );

const textTable = (blocks: readonly Block[]) =>
  Buffer.from(
    `module id, start, size:\n${blocks
      .map(
        ([start, size, segment]) =>
          `module[${String(segment).padStart(3)}]: 0x${start.toString(16).padStart(16, "0")}, ${String(size).padStart(3)}\n`,
      )
      .join("")}`,
  );

const drcov = (
  blocks: readonly Block[],
  {
    header = "DRCOV VERSION: 3\nDRCOV FLAVOR: drcov-64",
    table = 5,
    columns = LINUX_COLUMNS,
    rows = LINUX_ROWS,
    text = false,
  } = {},
) =>
  Buffer.concat([
    Buffer.from(
      `${header}\nModule Table: version ${String(table)}, count ${String(rows.length)}\nColumns: ${columns}\n${rows.join("\n")}\nBB Table: ${String(blocks.length)} bbs\n`,
    ),
    text ? textTable(blocks) : binaryTable(blocks),
  ]);

const RUN: readonly Block[] = [
  [0x100, 7, 0],
  [0x107, 5, 0],
  [0x115, 6, 0],
  [0x10c, 9, 0],
  [0x123, 4, 2],
  [0x123, 4, 2],
];

describe("drcov parsing", () => {
  it("reads DynamoRIO 3 logs with binary or text block tables alike", () => {
    const binary = parseDrcovLog(drcov(RUN));
    const text = parseDrcovLog(drcov(RUN, { text: true }));
    expect(binary).toMatchObject({
      version: 3,
      flavor: "drcov-64",
      moduleTableVersion: 5,
      blockTable: "binary",
    });
    expect(text.blockTable).toBe("text");
    for (const field of ["blockStarts", "blockSizes", "blockSegments"] as const)
      expect([...text[field]]).toEqual([...binary[field]]);
    expect(binary.segments[2]).toEqual({
      id: 2,
      containingId: 1,
      start: 0x7f5e9cdf7000n,
      end: 0x7f5e9cdfb000n,
      fileOffset: 0x2000n,
      preferredBase: 0x2000n,
      path: "/usr/bin/echo",
    });
  });

  it("keeps commas in paths and reads Windows checksum columns", () => {
    const log = parseDrcovLog(
      drcov([[0x10, 3, 0]], {
        table: 4,
        columns:
          "id, containing_id, start, end, entry, offset, checksum, timestamp, path",
        rows: [
          "  0,   0, 0x00007ff6a0000000, 0x00007ff6a0001000, 0x00007ff6a0001234, 0000000000000000, 0x0001a2b3, 0x5f000000,  C:\\Games\\Studio, Inc\\Game.exe",
        ],
      }),
    );
    expect(log.segments[0]).toMatchObject({
      path: "C:\\Games\\Studio, Inc\\Game.exe",
      preferredBase: null,
      fileOffset: 0n,
    });
  });

  it("reads Frida-style version 2 logs without containing modules", () => {
    const log = parseDrcovLog(
      drcov([[0x40, 8, 1]], {
        header: "DRCOV VERSION: 2\nDRCOV FLAVOR: frida",
        table: 2,
        columns: "id, base, end, entry, checksum, timestamp, path",
        rows: [
          "  0, 0x0000007a10000000, 0x0000007a10100000, 0x0000000000000000, 0x00000000, 0x00000000, /system/lib64/libc.so",
          "  1, 0x0000007b20000000, 0x0000007b24000000, 0x0000000000000000, 0x00000000, 0x00000000, /data/app/lib/arm64/libil2cpp.so",
        ],
      }),
    );
    const [libc, il2cpp] = drcovModules(log);
    expect(libc?.blocks).toEqual([]);
    expect(il2cpp?.blocks).toEqual([
      {
        offset: 0x40,
        image_offset: "0x40",
        static_address: null,
        runtime_address: "0x7b20000040",
        size: 8,
        segment_id: 1,
      },
    ]);
  });

  it.each([
    [
      "a version 1 module table",
      (log: string) => log.replace(/version 5, count 4/u, "4"),
      /version 1/u,
    ],
    [
      "a short module table",
      (log: string) => log.replace("count 4", "count 5"),
      /declares 5 rows/u,
    ],
    [
      "unknown columns",
      (log: string) => log.replace("offset,", "size,"),
      /Unsupported module table columns/u,
    ],
    [
      "a missing version line",
      (log: string) => log.replace("DRCOV VERSION: 3\n", ""),
      /DRCOV VERSION/u,
    ],
    [
      "out-of-order module ids",
      (log: string) => log.replace(" 3,   3,", " 4,   3,"),
      /has id 4/u,
    ],
  ])("rejects %s", (_name, mutate, message) => {
    const header = drcov([]).toString("latin1");
    expect(() => parseDrcovLog(Buffer.from(mutate(header), "latin1"))).toThrow(
      message,
    );
  });

  it("rejects truncated tables and blocks outside the module table", () => {
    expect(() => parseDrcovLog(drcov(RUN).subarray(0, -3))).toThrow(
      DrcovFormatError,
    );
    expect(() => parseDrcovLog(drcov([[0, 1, 9]]))).toThrow(
      /outside the module table/u,
    );
    expect(() => parseDrcovLog(Buffer.from("DRCOV VERSION: 3\n"))).toThrow(
      /no BB Table/u,
    );
  });
});

describe("drcov coverage", () => {
  it("groups segments, deduplicates blocks and derives addresses", () => {
    const modules = drcovModules(parseDrcovLog(drcov(RUN)));
    const echo = modules.find(({ path }) => path === "/usr/bin/echo");
    expect(echo?.segments.map(({ id }) => id)).toEqual([1, 2]);
    expect(echo?.blocks).toEqual([
      {
        offset: 0x2123,
        image_offset: "0x2123",
        static_address: "0x2123",
        runtime_address: "0x7f5e9cdf7123",
        size: 4,
        segment_id: 2,
      },
    ]);
    expect(summarizeModules(modules, null)).toEqual([
      {
        path: "/work/branchy",
        segments: 1,
        runtime_base: "0x400000",
        runtime_end: "0x401000",
        unique_blocks: 4,
        covered_bytes: 27,
        new_blocks: null,
        baseline_covered_bytes: null,
      },
      expect.objectContaining({ path: "/usr/bin/echo", unique_blocks: 1 }),
    ]);
  });

  it("keeps blocks with bytes the baseline never executed", () => {
    const run = drcovModules(parseDrcovLog(drcov(RUN)));
    // The baseline split [0x100, 0x10c) differently and missed 0x107-0x10b.
    const baseline = baselineRanges(
      drcovModules(
        parseDrcovLog(
          drcov([
            [0x100, 7, 0],
            [0x10c, 9, 0],
            [0x116, 5, 0],
          ]),
        ),
      ),
    );
    const branchy = run.find(({ path }) => path === "/work/branchy");
    if (branchy === undefined) throw new Error("fixture module missing");
    expect(newBlocks(branchy, baseline).map(({ offset }) => offset)).toEqual([
      0x107, 0x115,
    ]);
    expect(
      summarizeModules(run, baseline).map(({ path, new_blocks }) => [
        path,
        new_blocks,
      ]),
    ).toEqual([
      ["/work/branchy", 2],
      ["/usr/bin/echo", 1],
    ]);
  });
});
