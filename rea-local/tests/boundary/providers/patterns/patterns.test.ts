import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createBytePatternService,
  createCheatTableService,
} from "../../../../src/composition/patterns.js";
import type { BytePatternScan } from "../../../../src/domain/patterns/bytePatterns.js";
import type { CheatTableReport } from "../../../../src/domain/patterns/cheatTable.js";
import {
  createCheatTable,
  createPeImage,
  PE_IMAGE as PE,
} from "../../../fixtures/peImage.js";
import {
  createRadare2Elf,
  RADARE2_ELF_LAYOUT as ELF,
} from "../../../fixtures/radare2Elf.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const patterns = createBytePatternService();
const tables = createCheatTableService();
let root = "";
let pe = "";
let elf = "";
let table = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-patterns-")).root;
  pe = join(root, PE.name);
  elf = join(root, "fixture.elf");
  table = join(root, "Example.CT");
  await writeFile(pe, createPeImage());
  await writeFile(elf, createRadare2Elf());
  await writeFile(table, createCheatTable());
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const scan = async (input: Record<string, unknown>) => {
  const result = await patterns.scan(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as BytePatternScan;
};

const hex = (value: bigint | number) => `0x${value.toString(16)}`;

describe("scan_byte_patterns", () => {
  it("maps PE matches to sections and resolves rel32 targets", async () => {
    const report = await scan({
      path: pe,
      patterns: [
        { name: "player", pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0" },
        { pattern: "E8????????C3" },
        { pattern: "4? 8? C0" },
      ],
    });
    expect(report.file).toMatchObject({
      format: "pe",
      architecture: "amd64",
      image_base: hex(PE.imageBase),
      layout_error: null,
      sections: [
        {
          name: ".text",
          executable: true,
          address: hex(PE.imageBase + 0x1000n),
        },
        { name: ".data", executable: false },
      ],
    });
    expect(report.scanned).toEqual({
      scope: "executable",
      regions: [".text"],
      bytes: 0x200,
    });
    const [player, call, nibble] = report.results;
    expect(player).toMatchObject({
      name: "player",
      pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0",
      total_matches: 1,
      matches: [
        {
          file_offset: PE.textOffset,
          address: hex(PE.imageBase + 0x1000n),
          rva: "0x1000",
          section: ".text",
          displacements: [
            {
              pattern_offset: 3,
              value: 0xff9,
              target: hex(PE.imageBase + 0x2000n),
              target_section: ".data",
            },
          ],
        },
      ],
    });
    expect(call?.matches[0]).toMatchObject({
      rva: "0x100c",
      displacements: [
        { target: hex(PE.imageBase + 0x1100n), target_section: ".text" },
      ],
    });
    // 48 85 C0 at 0x1007 matches 4? 8? C0; nibble wildcards are kept in the text.
    expect(nibble).toMatchObject({ pattern: "4? 8? C0", total_matches: 1 });
  });

  it("reports overlapping matches and scans data with scope all", async () => {
    const all = await scan({
      path: pe,
      patterns: [{ pattern: "EF BE AD DE" }, { pattern: "00 00" }],
      scope: "all",
      max_matches: 3,
    });
    expect(all.results[0]?.matches[0]).toMatchObject({
      section: ".data",
      rva: "0x2000",
    });
    expect(all.results[1]?.total_matches).toBeGreaterThan(3);
    // 05 F9 0F 00 00 48 ... E8 EF 00 00 00: the last two hits overlap.
    expect(
      all.results[1]?.matches.map(({ file_offset }) => file_offset),
    ).toEqual([PE.textOffset + 5, PE.textOffset + 0xe, PE.textOffset + 0xf]);
  });

  it("resolves ELF calls through section headers", async () => {
    const report = await scan({
      path: elf,
      patterns: [{ pattern: "E8 ?? ?? ?? ??" }],
    });
    expect(report.file).toMatchObject({ format: "elf", image_base: null });
    expect(
      report.results[0]?.matches.map(({ address, displacements }) => [
        address,
        displacements[0]?.target,
      ]),
    ).toEqual([
      [hex(ELF.startCall), hex(ELF.checkKey)],
      [hex(ELF.checkKeyCall), hex(ELF.helper)],
    ]);
  });

  it("rejects malformed patterns before reading the file", async () => {
    const result = await patterns.scan({
      path: join(root, "missing.bin"),
      patterns: [
        { pattern: "48 GG" },
        { pattern: "?? ??" },
        { pattern: "48 8B" },
      ],
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          { path: ["patterns", 0, "pattern"] },
          {
            path: ["patterns", 1, "pattern"],
            message: expect.stringMatching(/fixed byte/u),
          },
        ],
      },
    });
  });
});

describe("inspect_cheat_table", () => {
  const inspect = async (input: Record<string, unknown>) => {
    const result = await tables.inspect(input);
    if (!result.ok) throw result.error;
    return result.value.normalized_result as CheatTableReport;
  };

  it("reads entries, scripts, symbols, structures and Lua", async () => {
    const report = await inspect({ path: table });
    expect(report.table).toMatchObject({
      table_version: 45,
      entries_total: 3,
      entries_truncated: false,
    });
    expect(report.entries).toMatchObject([
      { id: "0", path: ["Player"], group: true, children: 1 },
      {
        id: "1",
        path: ["Player", "Health"],
        type: "Float",
        address: '"game.exe"+2000',
        module: "game.exe",
        module_offset: "0x2000",
        offsets: ["10", "B8"],
        hotkeys: 1,
        script_lines: null,
      },
      {
        id: "2",
        description: "Infinite health & ammo",
        type: "Auto Assembler Script",
        script_lines: 11,
      },
    ]);
    expect(report.scripts).toEqual([
      {
        entry_id: "2",
        description: "Infinite health & ammo",
        aob_scans: [
          {
            kind: "aobscanmodule",
            symbol: "health",
            module: "game.exe",
            pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0",
          },
          {
            kind: "aobscanmodule",
            symbol: "other",
            module: "other.dll",
            pattern: "DE AD BE EF",
          },
        ],
        asserts: [
          {
            address: "game.exe+1000",
            module: "game.exe",
            offset: "0x1000",
            bytes: "48 8B 05 F9 0F 00 00",
          },
          {
            address: "game.exe+1007",
            module: "game.exe",
            offset: "0x1007",
            bytes: "90 90",
          },
        ],
        registered_symbols: ["health"],
        allocations: 1,
      },
    ]);
    expect(report).toMatchObject({
      symbols: [{ name: "playerBase", address: "game.exe+2000" }],
      structures: [
        {
          name: "Player",
          elements: [
            { offset: 16, type: "Float", size: 4, description: "health" },
            { offset: 184, type: "Pointer", size: 8, description: "stats" },
          ],
        },
      ],
      lua: { lines: 3 },
      binary_check: null,
    });
  });

  it("re-checks signatures and asserts against a module build", async () => {
    const report = await inspect({ path: table, binary_path: pe });
    expect(report.binary_check?.aob_scans).toMatchObject([
      {
        symbol: "health",
        applies: true,
        total_matches: 1,
        matches: [
          { rva: "0x1000", displacements: [{ target_section: ".data" }] },
        ],
      },
      { symbol: "other", applies: false, total_matches: 0 },
    ]);
    expect(report.binary_check?.asserts).toEqual([
      {
        entry_id: "2",
        address: "game.exe+1000",
        expected: "48 8B 05 F9 0F 00 00",
        actual: "488b05f90f0000",
        matches: true,
        reason: null,
      },
      {
        entry_id: "2",
        address: "game.exe+1007",
        expected: "90 90",
        actual: "4885",
        matches: false,
        reason: null,
      },
    ]);
  });

  it("rejects files that are not Cheat Engine tables", async () => {
    const other = join(root, "notes.xml");
    await writeFile(other, "<notes><note/></notes>");
    const broken = join(root, "broken.CT");
    await writeFile(broken, "<CheatTable><CheatEntries>");
    for (const path of [other, broken])
      expect(await tables.inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              path: ["path"],
              message: expect.stringContaining("Not a Cheat Engine table"),
            },
          ],
        },
      });
  });
});
