import { execFileSync } from "node:child_process";
import { chmod, readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { CoverageLog } from "../../../../src/domain/drcov/coverageLog.js";
import { createCoverageLogService } from "../../../../src/composition/coverage.js";
import {
  COVERAGE_ELF_BASE,
  COVERAGE_ELF_BLOCKS as BLOCKS,
  createCoverageElf,
} from "../../../fixtures/coverageElf.js";
import { createDrcovLog } from "../../../fixtures/drcovLog.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createCoverageLogService();
let root = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-coverage-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (
  input: Record<string, unknown>,
): Promise<CoverageLog> => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as CoverageLog;
};

const MODULES = [
  {
    path: "/games/Example/GameAssembly.so",
    segments: [
      [0x7f00_0000_0000n, 0x7f00_0001_0000n, 0n],
      [0x7f00_0001_0000n, 0x7f00_0010_0000n, 0x10000n],
    ],
  },
  {
    path: "/usr/lib/libc.so.6",
    segments: [[0x7f10_0000_0000n, 0x7f10_0020_0000n, 0n]],
  },
  {
    path: "/opt/mods/GameAssembly.so",
    segments: [[0x7f20_0000_0000n, 0x7f20_0001_0000n, 0n]],
  },
] as const;

const writeLog = async (
  name: string,
  blocks: Parameters<typeof createDrcovLog>[1],
) => {
  const path = join(root, name);
  await writeFile(path, createDrcovLog(MODULES, blocks));
  return path;
};

describe("synthesized drcov logs", () => {
  it("summarizes modules and pages one module's blocks", async () => {
    const path = await writeLog("jump.log", [
      [0x400, 12, 1],
      [0x40, 8, 3],
      [0x400, 12, 1],
      [0x900, 4, 1],
      [0x20, 6, 2],
    ]);
    const summary = await inspect({ path });
    expect(summary).toMatchObject({
      log: {
        drcov_version: 3,
        flavor: "drcov-64",
        module_table_version: 5,
        block_table: "binary",
        block_entries: 5,
      },
      baseline: null,
      selected_module: null,
      blocks: [],
      page: { total: 0, returned: 0 },
    });
    expect(summary.modules.map(({ path: module }) => module)).toEqual([
      "/games/Example/GameAssembly.so",
      "/opt/mods/GameAssembly.so",
      "/usr/lib/libc.so.6",
    ]);
    const page = await inspect({
      path,
      module: "/games/Example/GameAssembly.so",
      offset: 1,
      limit: 1,
    });
    expect(page.page).toEqual({ offset: 1, limit: 1, total: 2, returned: 1 });
    expect(page.blocks).toEqual([
      {
        image_offset: "0x10900",
        static_address: "0x10900",
        runtime_address: "0x7f0000010900",
        size: 4,
        segment_id: 1,
      },
    ]);
    expect(page.selected_module?.segments).toEqual([
      {
        id: 0,
        runtime_start: "0x7f0000000000",
        runtime_end: "0x7f0000010000",
        file_offset: "0x0",
        preferred_base: "0x0",
      },
      {
        id: 1,
        runtime_start: "0x7f0000010000",
        runtime_end: "0x7f0000100000",
        file_offset: "0x10000",
        preferred_base: "0x10000",
      },
    ]);
  });

  it("keeps only blocks the baseline did not execute", async () => {
    const path = await writeLog("action.log", [
      [0x400, 12, 1],
      [0x900, 4, 1],
      [0x20, 6, 2],
    ]);
    const baseline_path = await writeLog("idle.log", [
      [0x400, 12, 1],
      [0x20, 6, 2],
    ]);
    const diff = await inspect({
      path,
      baseline_path,
      module: "/games/Example/GameAssembly.so",
    });
    expect(diff.blocks.map(({ static_address }) => static_address)).toEqual([
      "0x10900",
    ]);
    expect(
      diff.modules.map(({ path: module, new_blocks }) => [module, new_blocks]),
    ).toEqual([
      ["/games/Example/GameAssembly.so", 1],
      ["/usr/lib/libc.so.6", 0],
    ]);
  });

  it("rejects ambiguous, unknown and self-baseline selections", async () => {
    const path = await writeLog("any.log", [[0x10, 1, 1]]);
    const text = join(root, "notes.txt");
    await writeFile(text, "not coverage");
    const cases = [
      [{ path, module: "GameAssembly.so" }, "module", /exact path/u],
      [{ path, module: "Missing.dll" }, "module", /No traced module/u],
      [{ path, baseline_path: path }, "baseline_path", /same log/u],
      [{ path: text }, "path", /Not a supported drcov log/u],
      [{ path: "relative.log" }, "path", /absolute/u],
    ] as const;
    for (const [input, field, message] of cases) {
      const result = await service.inspect(input);
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError", issues: [{ path: [field] }] },
      });
      if (!result.ok) expect(JSON.stringify(result.error)).toMatch(message);
    }
  });
});

const dynamorio = process.env.REA_VERIFY_DYNAMORIO_HOME;
const DYNAMORIO =
  dynamorio === undefined || dynamorio.length === 0 ? undefined : dynamorio;

describe.skipIf(DYNAMORIO === undefined || process.platform !== "linux")(
  "real DynamoRIO drcov lane (set REA_VERIFY_DYNAMORIO_HOME on Linux x86-64)",
  () => {
    const trace = async (name: string, args: string[], text = false) => {
      const directory = join(root, name);
      await mkdir(directory);
      execFileSync(
        join(DYNAMORIO ?? "", "bin64", "drrun"),
        [
          "-t",
          "drcov",
          ...(text ? ["-dump_text"] : []),
          "-logdir",
          directory,
          "--",
          join(root, "branchy"),
          ...args,
        ],
        { stdio: "pipe" },
      );
      const [log] = await readdir(directory);
      return join(directory, log ?? "missing");
    };
    const address = (offset: number) =>
      `0x${(COVERAGE_ELF_BASE + offset).toString(16)}`;

    beforeAll(async () => {
      const binary = join(root, "branchy");
      await writeFile(binary, createCoverageElf());
      await chmod(binary, 0o755);
    });

    it("isolates the blocks one argument adds", async () => {
      const idle = await trace("idle", []);
      const action = await trace("action", ["bonus"]);
      const textual = await trace("action-text", ["bonus"], true);
      expect(
        (await readFile(textual, "latin1")).includes("module id, start, size:"),
      ).toBe(true);
      const full = await inspect({ path: action, module: "branchy" });
      expect(full.log).toMatchObject({
        drcov_version: 3,
        block_table: "binary",
      });
      expect(
        full.blocks.map(({ static_address, size }) => [static_address, size]),
      ).toEqual(
        Object.values(BLOCKS)
          .sort((left, right) => left.offset - right.offset)
          .map(({ offset, size }) => [address(offset), size]),
      );
      const text = await inspect({ path: textual, module: "branchy" });
      expect(text.log.block_table).toBe("text");
      expect(text.blocks).toEqual(full.blocks);
      const diff = await inspect({
        path: action,
        baseline_path: idle,
        module: "branchy",
      });
      expect(diff.blocks.map(({ static_address }) => static_address)).toEqual([
        address(BLOCKS.call.offset),
        address(BLOCKS.bonus.offset),
      ]);
      expect(
        diff.modules.find(({ path }) => path.endsWith("/branchy")),
      ).toMatchObject({
        unique_blocks: 4,
        new_blocks: 2,
        covered_bytes: 27,
      });
    });
  },
);
