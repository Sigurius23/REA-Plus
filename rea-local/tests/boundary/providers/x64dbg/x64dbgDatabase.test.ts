import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createX64dbgDatabaseService } from "../../../../src/composition/x64dbg.js";
import type { X64dbgDatabaseReport } from "../../../../src/domain/x64dbg/x64dbgDatabase.js";
import { createPeImage, PE_IMAGE } from "../../../fixtures/peImage.js";
import {
  compressX64dbgDatabase,
  createX64dbgDatabase,
  X64DBG_DATABASE,
} from "../../../fixtures/x64dbgFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createX64dbgDatabaseService();
let root = "";
const paths = { plain: "", compressed: "", module: "" };

beforeAll(async () => {
  root = (await createTestWorkspace("rea-x64dbg-")).root;
  paths.plain = join(root, "game.exe.dd64");
  paths.compressed = join(root, "compressed.dd64");
  paths.module = join(root, PE_IMAGE.name);
  await writeFile(paths.plain, createX64dbgDatabase());
  // Small blocks exercise multi-block frames.
  await writeFile(
    paths.compressed,
    compressX64dbgDatabase(createX64dbgDatabase(), 700),
  );
  await writeFile(paths.module, createPeImage());
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as X64dbgDatabaseReport;
};

describe("x64dbg databases", () => {
  it("summarises plain and LZ4-compressed databases alike", async () => {
    const plain = await inspect({ path: paths.plain });
    const compressed = await inspect({ path: paths.compressed });
    expect(plain.database).toMatchObject({
      compressed: false,
      hash_algorithm: "murmurhash",
      debuggee_hash: "0xDEADBEEF12345678",
      modules: ["game.exe", "kernel32.dll", "steam_api64.dll"],
      notes: X64DBG_DATABASE.notes,
      init_script: "C:\\scripts\\init.txt",
      plugins: ["xAnalyzer"],
    });
    expect(compressed.database).toMatchObject({
      compressed: true,
      json_bytes: plain.database.bytes,
    });
    expect(compressed.summary).toEqual(plain.summary);
    expect(plain.summary).toEqual({
      labels: 3,
      comments: 1,
      bookmarks: 1,
      functions: 2,
      arguments: 1,
      loops: 1,
      breakpoints: 4,
      xrefs: 1,
      watch: 1,
      mismatched_breakpoints: null,
    });
    expect(compressed.labels).toEqual(plain.labels);
  });

  it("lists annotations and ranges", async () => {
    const labels = await inspect({ path: paths.plain });
    expect(
      labels.labels.map(({ address, manual, text }) => [address, manual, text]),
    ).toEqual([
      ["0x1000", true, "LoadHealth"],
      ["0x1100", false, "helper"],
      ["0x1011", false, "legacy_return"],
    ]);
    const functions = await inspect({
      path: paths.plain,
      view: "functions",
      module: "GAME.EXE",
    });
    expect(functions.functions).toEqual([
      {
        module: "game.exe",
        start: "0x1000",
        end: "0x1011",
        manual: true,
        instructions: 5,
        parent: "0x1000",
        depth: null,
        file_offset: null,
        section: null,
      },
    ]);
    const loops = await inspect({ path: paths.plain, view: "loops" });
    expect(loops.loops[0]).toMatchObject({
      depth: 0,
      parent: null,
      instructions: 3,
    });
    const xrefs = await inspect({ path: paths.plain, view: "xrefs" });
    expect(xrefs.xrefs[0]?.references).toEqual([
      { address: "0x100C", type: 2 },
    ]);
    const watch = await inspect({ path: paths.plain, view: "watch" });
    expect(watch.watch).toEqual([
      {
        name: "hp",
        expression: "[rax+0x10]",
        data_type: "int",
        watchdog: "Changed",
      },
    ]);
    const query = await inspect({
      path: paths.plain,
      view: "comments",
      query: "HEALTH",
    });
    expect(query.page).toMatchObject({ total: 1, returned: 1 });
  });
});

describe("x64dbg databases with their module", () => {
  it("places entries in the module and checks breakpoint bytes against it", async () => {
    const report = await inspect({
      path: paths.plain,
      view: "breakpoints",
      module_path: paths.module,
    });
    expect(report.module_file).toMatchObject({
      name: "game.exe",
      format: "pe",
      image_base: "0x140000000",
    });
    expect(
      report.breakpoints.map(
        ({ address, type, file_offset, section, old_bytes, bytes_match }) => [
          address,
          type,
          file_offset,
          section,
          old_bytes,
          bytes_match,
        ],
      ),
    ).toEqual([
      ["0x1000", "software", 0x200, ".text", "488b", true],
      ["0x1007", "software", 0x207, ".text", "9090", false],
      ["0x2000", "memory", 0x400, ".data", null, null],
      ["0x0", "dll", null, null, null, null],
    ]);
    expect(report.summary.mismatched_breakpoints).toBe(1);
    expect(report.breakpoints[0]).toMatchObject({
      name: "health read",
      break_condition: "rax==0",
      log_text: "hp={rax}",
      enabled: true,
    });
    expect(report.breakpoints[2]).toMatchObject({
      command_text: "dump rax",
      fast_resume: true,
      silent: true,
    });
    const labels = await inspect({
      path: paths.plain,
      module_path: paths.module,
    });
    expect(labels.labels.map(({ file_offset }) => file_offset)).toEqual([
      0x200, 0x300, 0x211,
    ]);
  });

  it("refuses files that are not x64dbg databases", async () => {
    const text = join(root, "notes.txt");
    await writeFile(text, "not json");
    const truncated = join(root, "truncated.dd64");
    await writeFile(
      truncated,
      compressX64dbgDatabase(createX64dbgDatabase()).subarray(0, 40),
    );
    for (const path of [text, truncated])
      expect(await service.inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              message: expect.stringContaining(
                "Not a readable x64dbg database",
              ),
            },
          ],
        },
      });
    expect(
      await service.inspect({ path: paths.plain, module_path: "game.exe" }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["module_path"] }] },
    });
  });
});

/** The lz4 command (1.9.x); `lz4 -l` writes the same legacy frame as x64dbg's lz4file. */
const LZ4 = process.env["REA_VERIFY_LZ4_BIN"];

describe.skipIf(LZ4 === undefined)(
  "databases compressed by the lz4 tool",
  () => {
    it.each([
      ["one block", createX64dbgDatabase()],
      [
        "several 8 MiB blocks",
        createX64dbgDatabase({
          ...X64DBG_DATABASE,
          comments: Array.from({ length: 120_000 }, (_, index) => ({
            module: "game.exe",
            address: `0x${(0x1000 + index).toString(16).toUpperCase()}`,
            manual: true,
            text: `comment ${String(index)} ${"x".repeat(index % 97)}`,
          })),
        }),
      ],
    ])(
      "reads %s",
      async (_name, json) => {
        const source = join(root, "lz4-source.json");
        const target = join(root, "lz4.dd64");
        await writeFile(source, json);
        await promisify(execFile)(LZ4 ?? "lz4", [
          "-l",
          "-f",
          "-q",
          source,
          target,
        ]);
        const report = await inspect({
          path: target,
          view: "comments",
          limit: 1,
        });
        expect(report.database).toMatchObject({
          compressed: true,
          json_bytes: json.length,
        });
        expect(report.summary.comments).toBe(
          JSON.parse(json.toString("utf8")).comments.length,
        );
      },
      120_000,
    );
  },
);
