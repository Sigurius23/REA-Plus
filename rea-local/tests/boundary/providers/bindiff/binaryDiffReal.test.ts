import { execFile } from "node:child_process";
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createBinaryDiffService } from "../../../../src/composition/binaryDiff.js";
import type { BinaryDiffReport } from "../../../../src/domain/bindiff/binaryDiff.js";
import {
  elfFunctionSymbols,
  sourceName,
} from "../../../support/bindiff/elfSymbols.js";
import { gameSource } from "../../../support/bindiff/gameSource.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/**
 * Real-tool lanes. REA_VERIFY_BINDIFF_CC is a C compiler; each build is
 * compiled twice, stripped for the diff and unstripped for its symbols, the
 * answer key. The diff runs through radare2 (REA_VERIFY_RADARE2_PATH) and
 * Rizin (REA_VERIFY_RIZIN_PATH). REA_VERIFY_BINDIFF_ZLIB and
 * REA_VERIFY_BINDIFF_LUA are folders holding zlib-v1.2.13 and zlib-v1.3.1,
 * or lua-v5.4.0 and lua-v5.4.6, source checkouts.
 */
const setting = (name: string) => {
  const value = process.env[name];
  return value === undefined || value.length === 0 ? undefined : value;
};
const CC = setting("REA_VERIFY_BINDIFF_CC");
const ZLIB = setting("REA_VERIFY_BINDIFF_ZLIB");
const LUA = setting("REA_VERIFY_BINDIFF_LUA");
const ENGINES = [
  ["radare2", setting("REA_VERIFY_RADARE2_PATH")],
  ["rizin", setting("REA_VERIFY_RIZIN_PATH")],
] as const;
const run = promisify(execFile);
const FLAGS = ["-O2", "-fno-stack-protector", "-w"];

let root = "";
beforeAll(async () => {
  root = (await createTestWorkspace("rea-bindiff-real-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

/** Compile sources into an unstripped and a stripped executable. */
const build = async (
  name: string,
  sources: readonly string[],
  options: { readonly cwd?: string; readonly flags?: readonly string[] } = {},
) => {
  const plain = join(root, name);
  for (const [output, extra] of [
    [plain, []],
    [`${plain}.stripped`, ["-s"]],
  ] as const)
    await run(
      CC ?? "",
      [
        ...FLAGS,
        ...(options.flags ?? []),
        "-o",
        output,
        ...sources,
        ...extra,
        "-lm",
        "-ldl",
      ],
      { cwd: options.cwd ?? root, timeout: 300_000 },
    );
  return {
    stripped: `${plain}.stripped`,
    symbols: await elfFunctionSymbols(plain),
  };
};

/** Diff two stripped builds and score every match against their symbols. */
const score = async (
  engine: string,
  older: Awaited<ReturnType<typeof build>>,
  newer: Awaited<ReturnType<typeof build>>,
) => {
  const service = createBinaryDiffService({
    ...process.env,
    REA_ANALYSIS_PROVIDER: "radare2",
    REA_RADARE2_PATH: engine,
  });
  try {
    const page = async (input: Record<string, unknown>) => {
      const result = await service.inspect({
        left: older.stripped,
        right: newer.stripped,
        names: false,
        limit: 1000,
        ...input,
      });
      if (!result.ok) throw result.error;
      return result.value.normalized_result as BinaryDiffReport;
    };
    const summary = await page({});
    const functions = (await page({ view: "functions" })).functions;
    const unmatched = (await page({ view: "unmatched" })).unmatched;
    const truth = (side: "left" | "right", address: string) => {
      const name = (side === "left" ? older : newer).symbols.get(address);
      return name === undefined ? undefined : sourceName(name);
    };
    let correct = 0;
    const wrong: string[] = [];
    for (const row of functions) {
      const a = truth("left", row.left.address);
      const b = truth("right", row.right.address);
      if (a === undefined || b === undefined) continue;
      if (a === b) correct += 1;
      else wrong.push(`${a} -> ${b} (${row.method} ${String(row.similarity)})`);
    }
    const rightNames = new Set(
      [...newer.symbols.values()].map((name) => sourceName(name)),
    );
    const analyzedLeft = new Set([
      ...functions.map(({ left }) => left.address),
      ...unmatched
        .filter(({ status }) => status === "removed")
        .map(({ address }) => address),
    ]);
    const possible = [...analyzedLeft].filter((address) => {
      const name = truth("left", address);
      return name !== undefined && rightNames.has(name);
    }).length;
    const named = (
      rows: readonly { address: string; status: string }[],
      status: string,
      side: "left" | "right",
    ) =>
      rows
        .filter((row) => row.status === status)
        .map((row) => truth(side, row.address));
    return {
      summary,
      functions,
      correct,
      possible,
      wrong,
      changed: functions
        .filter(({ status }) => status === "changed")
        .map(({ left }) => truth("left", left.address)),
      removed: named(unmatched, "removed", "left"),
      added: named(unmatched, "added", "right"),
    };
  } finally {
    await service.close();
  }
};

for (const [engine, path] of ENGINES)
  describe.skipIf(CC === undefined || path === undefined)(
    `diff_binaries through ${engine}`,
    () => {
      it("finds the changed, removed and added functions of a two-version program", async () => {
        const sources = await Promise.all(
          [false, true].map(async (newer) => {
            const file = join(root, `game-${String(newer)}.c`);
            await writeFile(file, gameSource(newer));
            return file;
          }),
        );
        // Keep each function whole so every change has a function to land in.
        const older = await build(`game-${engine}-1.0`, [sources[0] ?? ""], {
          flags: ["-fno-inline"],
        });
        const newer = await build(`game-${engine}-1.1`, [sources[1] ?? ""], {
          flags: ["-fno-inline"],
        });
        const result = await score(path ?? "", older, newer);
        expect(result.wrong).toEqual([]);
        expect(result.correct).toBe(result.possible);
        expect(result.changed).toContain("update_player");
        expect(result.removed).toContain("old_cheat_check");
        expect(result.added).toEqual(
          expect.arrayContaining(["anti_tamper", "log_frame"]),
        );
        const update = result.functions.find(
          (row) =>
            sourceName(older.symbols.get(row.left.address) ?? "") ===
            "update_player",
        );
        expect(update?.calls_removed.length).toBeGreaterThan(0);
        expect(update?.calls_added.length).toBeGreaterThan(0);
      }, 600_000);

      it.skipIf(ZLIB === undefined)(
        "matches stripped zlib 1.2.13 and 1.3.1 builds without a wrong pair",
        async () => {
          const minigzip = async (version: string) => {
            const dir = join(ZLIB ?? "", `zlib-${version}`);
            const files = (await readdir(dir))
              .filter(
                (file) => file.endsWith(".c") && !file.startsWith("example"),
              )
              .map((file) => join(dir, file));
            return build(
              `minigzip-${engine}-${version}`,
              [...files, join(dir, "test", "minigzip.c")],
              {
                cwd: dir,
                flags: [
                  "-I",
                  dir,
                  "-D_LARGEFILE64_SOURCE=1",
                  "-DHAVE_UNISTD_H",
                ],
              },
            );
          };
          const result = await score(
            path ?? "",
            await minigzip("v1.2.13"),
            await minigzip("v1.3.1"),
          );
          expect(result.wrong).toEqual([]);
          expect(result.correct / result.possible).toBeGreaterThanOrEqual(0.97);
        },
        900_000,
      );

      it.skipIf(LUA === undefined)(
        "matches most of stripped Lua 5.4.0 and 5.4.6 interpreters",
        async () => {
          const lua = async (version: string) => {
            const dir = join(LUA ?? "", `lua-${version}`);
            const files = (await readdir(dir))
              .filter(
                (file) =>
                  file.endsWith(".c") &&
                  !["luac.c", "onelua.c", "ltests.c"].includes(file),
              )
              .map((file) => join(dir, file));
            return build(`lua-${engine}-${version}`, files, {
              cwd: dir,
              flags: ["-DLUA_USE_LINUX"],
            });
          };
          const result = await score(
            path ?? "",
            await lua("v5.4.0"),
            await lua("v5.4.6"),
          );
          // Renamed functions (luaE_enterCcall became luaE_incCstack) count as wrong here.
          expect(result.wrong.length / result.correct).toBeLessThanOrEqual(
            0.03,
          );
          expect(result.correct / result.possible).toBeGreaterThanOrEqual(0.9);
        },
        1_800_000,
      );
    },
  );
