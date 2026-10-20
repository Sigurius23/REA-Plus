import { execFile } from "node:child_process";
import { cp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createRenpyScriptService } from "../../../../src/composition/renpy.js";
import type { RenpyScriptReport } from "../../../../src/domain/renpy/renpyScript.js";
import {
  createHostileRenpyScript,
  createLegacyRenpyScript,
  createRenpyScript,
} from "../../../fixtures/renpyScriptFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createRenpyScriptService();
let root = "";
let script = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-renpy-")).root;
  script = join(root, "script.rpyc");
  await writeFile(script, createRenpyScript());
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as RenpyScriptReport;
};

describe("compiled Ren'Py scripts", () => {
  it("summarises the script and maps labels and their flow", async () => {
    const report = await inspect({ path: script });
    expect(report.script).toMatchObject({
      format: "rpyc2",
      slot: 2,
      script_version: 5003000,
      source_files: ["game/script.rpy"],
    });
    expect(report.summary).toMatchObject({
      labels: 3,
      dialogue: 4,
      menus: 1,
      languages: ["french"],
      speakers: [
        { who: "e", lines: 2 },
        { who: null, lines: 1 },
      ],
    });
    expect(report.labels).toEqual([
      {
        name: "start",
        file: "game/script.rpy",
        line: 5,
        statements: 6,
        dialogue: 2,
        menus: 1,
        jumps: ["left", "left"],
        calls: ["book_talk"],
      },
      {
        name: "left",
        file: "game/script.rpy",
        line: 16,
        statements: 2,
        dialogue: 1,
        menus: 0,
        jumps: ["expression ending"],
        calls: [],
      },
      {
        name: "book_talk",
        file: "game/script.rpy",
        line: 20,
        statements: 1,
        dialogue: 0,
        menus: 0,
        jumps: [],
        calls: [],
      },
    ]);
  });

  it("lists dialogue with translation identifiers and translations", async () => {
    const dialogue = await inspect({ path: script, view: "dialogue" });
    expect(dialogue.dialogue).toEqual([
      {
        label: "start",
        file: "game/script.rpy",
        line: 6,
        who: "e",
        what: "Hello, {b}world{/b}! 100%% sure.",
        identifier: "start_1a2b3c4d",
        language: null,
      },
      expect.objectContaining({ who: null, identifier: "start_5e6f7a8b" }),
      expect.objectContaining({ label: "left", what: "You went left." }),
      expect.objectContaining({
        label: null,
        identifier: "start_1a2b3c4d",
        language: "french",
        what: "Bonjour, {b}le monde{/b} !",
      }),
    ]);
    const route = await inspect({
      path: script,
      view: "dialogue",
      label: "left",
    });
    expect(route.dialogue.map(({ what }) => what)).toEqual(["You went left."]);
    const translations = await inspect({ path: script, view: "translations" });
    expect(translations.translations).toEqual([
      expect.objectContaining({
        kind: "block",
        language: "french",
        identifier: "start_1a2b3c4d",
      }),
      expect.objectContaining({
        kind: "string",
        language: "french",
        old: "Go left",
        new: "Aller à gauche",
      }),
    ]);
  });
});

describe("compiled Ren'Py script views", () => {
  it("lists menus and definitions", async () => {
    const menus = await inspect({ path: script, view: "menus" });
    expect(menus.menus).toEqual([
      {
        label: "start",
        file: "game/script.rpy",
        line: 9,
        caption: "Where to?",
        choices: [
          { text: "Go left", condition: "True", jumps: ["left"], calls: [] },
          {
            text: "Ask about the {i}book{/i}",
            condition: "met_eileen",
            jumps: ["left"],
            calls: ["book_talk"],
          },
        ],
      },
    ]);
    const definitions = await inspect({ path: script, view: "definitions" });
    expect(
      definitions.definitions.map(({ kind, name, value }) => [
        kind,
        name,
        value,
      ]),
    ).toEqual([
      ["define", "e", 'Character("Eileen")'],
      ["default", "met_eileen", "False"],
      ["image", "bg room", '"room.png"'],
      ["screen", "hud", null],
    ]);
    const query = await inspect({
      path: script,
      view: "definitions",
      query: "eileen",
    });
    expect(query.page).toMatchObject({ total: 2, returned: 2 });
  });

  it("reads slot 1 only and pre-6.18 zlib-only scripts", async () => {
    const slot1 = join(root, "slot1.rpyc");
    await writeFile(slot1, createRenpyScript({ slots: [1] }));
    const slotOne = await inspect({ path: slot1, view: "dialogue" });
    expect(slotOne.script.slot).toBe(1);
    // Slot 1 holds plain Say nodes: identifiers come only from translate blocks.
    expect(slotOne.dialogue.map(({ identifier }) => identifier)).toEqual([
      null,
      null,
      null,
      "start_1a2b3c4d",
    ]);
    const legacy = join(root, "legacy.rpyc");
    await writeFile(legacy, createLegacyRenpyScript());
    const old = await inspect({ path: legacy });
    expect(old.script).toMatchObject({ format: "rpyc1", slot: null });
    expect(old.summary.labels).toBe(3);
  });

  it("refuses scripts that name code outside Ren'Py", async () => {
    const path = join(root, "hostile.rpyc");
    await writeFile(path, createHostileRenpyScript());
    expect(await service.inspect({ path })).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          {
            path: ["path"],
            message: expect.stringMatching(/refusing global posix\.system/u),
          },
        ],
      },
    });
    const text = join(root, "script.rpy");
    await writeFile(text, 'label start:\n    "Hi."\n');
    expect(await service.inspect({ path: text })).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          { message: expect.stringContaining("Not a readable Ren'Py script") },
        ],
      },
    });
  });
});

/** The Ren'Py SDK root (renpy-8.x-sdk), whose sample games ship .rpyc beside .rpy. */
const SDK = process.env["REA_VERIFY_RENPY_SDK"];

const rpycFiles = async (directory: string): Promise<string[]> => {
  const found: string[] = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).isDirectory())
      found.push(...(await rpycFiles(path)));
    else if (name.endsWith(".rpyc")) found.push(path);
  }
  return found;
};

/** Ren'Py's `dialogue` command output: extend-like speakers, combine_filter, TSV escapes. */
const asRenpyTab = (rows: RenpyScriptReport["dialogue"]): string[] => {
  let prior = "";
  const combine = (text: string) => {
    let out = text;
    for (const double of ["{{", "%%"])
      while (out.includes(double)) {
        const at = out.indexOf(double);
        out = out.slice(0, at) + out.slice(at + 1);
      }
    return out;
  };
  return rows.map((row) => {
    let who = row.who ?? "";
    if (who === "extend") who = `extend ${prior}`;
    else prior = who;
    const what = combine(row.what)
      .replaceAll("\\", "\\\\")
      .replaceAll("\t", "\\t")
      .replaceAll("\n", "\\n");
    return [row.identifier, who, what, row.file, String(row.line)].join("\t");
  });
};

describe.skipIf(SDK === undefined)("real Ren'Py SDK scripts", () => {
  const sdk = SDK ?? "";

  it("decodes every .rpyc the SDK ships", async () => {
    const files = await rpycFiles(sdk);
    expect(files.length).toBeGreaterThan(100);
    for (const path of files) {
      const result = await service.inspect({ path, limit: 1 });
      expect(result.ok, path).toBe(true);
    }
  });

  it.each(["the_question", "tutorial"])(
    "matches Ren'Py's own dialogue extraction for %s",
    async (game) => {
      const copy = join(root, game);
      await cp(join(sdk, game), copy, { recursive: true });
      await promisify(execFile)(
        join(sdk, "renpy.sh"),
        [copy, "dialogue", "None"],
        {
          env: {
            ...process.env,
            HOME: root,
            SDL_VIDEODRIVER: "dummy",
            SDL_AUDIODRIVER: "dummy",
          },
          timeout: 300_000,
        },
      );
      const expected = (await readFile(join(copy, "dialogue.tab"), "utf8"))
        .trim()
        .split("\n")
        .slice(1)
        .map((line) => line.split("\t").slice(0, 5).join("\t"));
      const files = new Set(expected.map((line) => line.split("\t")[3] ?? ""));
      const actual: string[] = [];
      for (const file of files) {
        const report = await inspect({
          path: join(copy, `${file.replace(/^game\//u, "game/")}c`),
          view: "dialogue",
          limit: 1000,
        });
        actual.push(
          ...asRenpyTab(
            report.dialogue.filter(({ language }) => language === null),
          ),
        );
      }
      expect(actual.sort()).toEqual(expected.sort());
    },
  );
});
