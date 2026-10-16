import { createHash } from "node:crypto";
import { readdirSync, statSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGameMakerDataService } from "../../../../src/composition/gameMaker.js";
import type { GameMakerDataReport } from "../../../../src/domain/gamemaker/gameMakerData.js";
import {
  appendToRunner,
  createGameMakerAudioGroup,
  createGameMakerData,
  createMisalignedGameMakerData,
  FIXTURE_PNG,
  FIXTURE_STRINGS,
} from "../../../fixtures/gameMakerFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createGameMakerDataService();
let root = "";
const files: Record<string, string> = {};

beforeAll(async () => {
  root = (await createTestWorkspace("rea-gamemaker-")).root;
  const write = async (name: string, bytes: Buffer) => {
    files[name] = join(root, name);
    await writeFile(files[name], bytes);
  };
  await write("data.win", createGameMakerData());
  await write("old.win", createGameMakerData({ bytecode: 14 }));
  await write("yyc.win", createGameMakerData({ yyc: true }));
  await write("runner.exe", appendToRunner(createGameMakerData()));
  await write("audiogroup1.dat", createGameMakerAudioGroup());
  await write("misaligned.win", createMisalignedGameMakerData());
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as GameMakerDataReport;
};

describe("GameMaker data files", () => {
  it("reads GEN8, the chunk table and counts", async () => {
    const report = await inspect({ path: files["data.win"] });
    expect(report.general).toEqual({
      name: "fixture_game",
      display_name: "Fixture Game",
      file_name: "fixture_game",
      config: "Default",
      game_id: 4242,
      bytecode_version: 17,
      stored_version: "2.0.0.0",
      minimum_version: "2.3",
      compiled: "vm",
      debugger_disabled: true,
      window: { width: 640, height: 360 },
      flags: ["scale", "show_cursor", "steam_enabled"],
      built_at: "2026-01-01T00:00:00.000Z",
      steam_app_id: 480,
      room_order: 1,
    });
    expect(report.chunks.map(({ name, entries }) => [name, entries])).toEqual([
      ["GEN8", null],
      ["SOND", 2],
      ["AGRP", 1],
      ["SPRT", 1],
      ["SCPT", 2],
      ["OBJT", 2],
      ["ROOM", 1],
      ["SEQN", 1],
      ["CODE", 4],
      ["VARI", null],
      ["FUNC", null],
      ["STRG", FIXTURE_STRINGS.length],
      ["TXTR", 3],
      ["AUDO", 2],
    ]);
    expect(report.summary).toMatchObject({
      code: 4,
      strings: FIXTURE_STRINGS.length,
      functions: 2,
      variables: 2,
      textures: 3,
      audio: 2,
    });
    expect(report.file).toMatchObject({ form_offset: 0 });
  });

  it("lists resources with cross-referenced names", async () => {
    const report = await inspect({
      path: files["data.win"],
      view: "resources",
      limit: 50,
    });
    const by = (kind: string) =>
      report.resources
        .filter((row) => row.kind === kind)
        .map(({ name, fields }) => [name, fields]);
    expect(by("sound")).toEqual([
      [
        "snd_jump",
        {
          type: ".ogg",
          file: "snd_jump.ogg",
          volume: 1,
          pitch: 1,
          audio_group: 0,
          audio_file: 0,
        },
      ],
      [
        "snd_music",
        {
          type: ".mp3",
          file: "music.ogg",
          volume: 0.5,
          pitch: 1,
          audio_group: 1,
          audio_file: 3,
        },
      ],
    ]);
    expect(by("sprite")).toEqual([
      ["spr_player", { width: 32, height: 48, origin_x: 16, origin_y: 48 }],
    ]);
    expect(by("script")).toEqual([
      ["scr_move", { code: "gml_Script_scr_move", constructor: false }],
      ["Player", { code: "gml_GlobalScript_Player", constructor: true }],
    ]);
    expect(by("object")).toEqual([
      ["obj_player", { sprite: "spr_player", visible: true }],
      ["obj_wall", { sprite: null, visible: false }],
    ]);
    expect(by("room")).toEqual([
      [
        "rm_start",
        {
          caption: "Start",
          width: 640,
          height: 360,
          speed: 60,
          persistent: true,
          creation_code: "gml_Room_rm_start_Create",
          instances: 2,
        },
      ],
    ]);
    expect(by("sequence")).toEqual([["seq_intro", {}]]);
    const objects = await inspect({
      path: files["data.win"],
      view: "resources",
      kind: "object",
      query: "WALL",
    });
    expect(objects.resources.map(({ name }) => name)).toEqual(["obj_wall"]);
  });
});

describe("GameMaker data contents", () => {
  it("lists code, symbols, strings, textures and audio", async () => {
    const code = await inspect({ path: files["data.win"], view: "code" });
    expect(
      code.code.map(({ name, length, locals, arguments: args, shared }) => [
        name,
        length,
        locals,
        args,
        shared,
      ]),
    ).toEqual([
      ["gml_Script_scr_move", 8, 1, 2, false],
      ["gml_GlobalScript_Player", 12, 0, 0, false],
      ["gml_Script_Player", 12, 3, 1, true],
      ["gml_Room_rm_start_Create", 4, 0, 0, false],
    ]);
    expect(code.code[1]?.bytecode_offset).toBe(code.code[2]?.bytecode_offset);
    const symbols = await inspect({ path: files["data.win"], view: "symbols" });
    expect(
      symbols.symbols.map(({ kind, name, occurrences, instance_type }) => [
        kind,
        name,
        occurrences,
        instance_type,
      ]),
    ).toEqual([
      ["function", "instance_create_layer", 2, null],
      ["function", "show_debug_message", 5, null],
      ["variable", "score", 4, -5],
      ["variable", "hp", 7, -1],
    ]);
    const strings = await inspect({
      path: files["data.win"],
      view: "strings",
      query: "rm_start",
    });
    expect(strings.strings.map(({ text }) => text)).toEqual([
      "rm_start",
      "gml_Room_rm_start_Create",
    ]);
    const textures = await inspect({
      path: files["data.win"],
      view: "textures",
    });
    expect(
      textures.textures.map(({ format, width, height }) => [
        format,
        width,
        height,
      ]),
    ).toEqual([
      ["png", 16, 8],
      ["qoi", 8, 4],
      ["external", null, null],
    ]);
    expect(textures.textures[0]?.span).toBeGreaterThanOrEqual(
      FIXTURE_PNG.length,
    );
    const audio = await inspect({ path: files["data.win"], view: "audio" });
    expect(
      audio.audio.map(({ format, bytes, sounds }) => [format, bytes, sounds]),
    ).toEqual([
      ["wav", 12, ["snd_jump"]],
      ["ogg", 8, []],
    ]);
  });
});

describe("GameMaker data variants", () => {
  it("reads bytecode 14, YYC, appended and audio-group files", async () => {
    const old = await inspect({ path: files["old.win"], view: "code" });
    expect(old.general?.bytecode_version).toBe(14);
    expect(old.code.map(({ name, locals }) => [name, locals])).toEqual([
      ["gml_Script_scr_move", null],
      ["gml_GlobalScript_Player", null],
      ["gml_Script_Player", null],
      ["gml_Room_rm_start_Create", null],
    ]);
    expect(
      (await inspect({ path: files["old.win"], view: "symbols" })).symbols,
    ).toHaveLength(4);
    const yyc = await inspect({ path: files["yyc.win"] });
    expect(yyc.general?.compiled).toBe("yyc");
    expect(yyc.summary).toMatchObject({ code: 0, functions: 0, variables: 0 });
    expect(yyc.limitations).toContain(
      "Compiled with YYC: game logic is native code in the executable, not bytecode in this file.",
    );
    const runner = await inspect({
      path: files["runner.exe"],
      view: "resources",
      kind: "room",
    });
    expect(runner.file.form_offset).toBe(1024);
    expect(runner.resources[0]).toMatchObject({
      name: "rm_start",
      offset:
        1024 +
        (
          await inspect({
            path: files["data.win"],
            view: "resources",
            kind: "room",
          })
        ).resources[0]!.offset,
    });
    const group = await inspect({
      path: files["audiogroup1.dat"],
      view: "audio",
    });
    expect(group.general).toBeNull();
    expect(group.audio.map(({ format }) => format)).toEqual(["wav", "ogg"]);
  });

  it("refuses references that miss the string table and non-GameMaker files", async () => {
    expect(
      await service.inspect({ path: files["misaligned.win"] }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          {
            message: expect.stringMatching(/does not point at a STRG string/u),
          },
        ],
      },
    });
    const text = join(root, "notes.txt");
    await writeFile(text, "FORMless text");
    expect(await service.inspect({ path: text })).toMatchObject({
      ok: false,
      error: {
        issues: [
          {
            message: expect.stringContaining(
              "Not a readable GameMaker data file",
            ),
          },
        ],
      },
    });
  });
});

/** Folders of real GameMaker data files (data.win, game.droid, audiogroupN.dat, ...). */
const REAL = process.env["REA_VERIFY_GAMEMAKER_DIR"];
const realFiles = (directory: string): string[] =>
  readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) return realFiles(path);
    return /^(data\.win|game\.(unx|droid|ios)|audiogroup\d+\.dat)$/iu.test(name)
      ? [path]
      : [];
  });

describe.skipIf(REAL === undefined)("real GameMaker data files", () => {
  it.each(REAL === undefined ? [] : realFiles(REAL))(
    "is consistent for %s",
    async (path) => {
      const all = async (view: string) => inspect({ path, view, limit: 1000 });
      const overview = await all("chunks");
      // The chunks tile the FORM exactly.
      expect(
        overview.chunks.reduce((sum, chunk) => sum + 8 + chunk.size, 0),
      ).toBe(overview.file.form_size);
      const code = await all("code");
      const codeChunk = overview.chunks.find(({ name }) => name === "CODE");
      for (const entry of code.code) {
        expect(entry.bytecode_offset ?? 0).toBeGreaterThanOrEqual(
          (codeChunk?.offset ?? 0) + 8,
        );
        expect((entry.bytecode_offset ?? 0) + entry.length).toBeLessThanOrEqual(
          (codeChunk?.offset ?? 0) + 8 + (codeChunk?.size ?? 0),
        );
      }
      const textures = await all("textures");
      for (const texture of textures.textures) {
        expect(texture.format).not.toBe("unknown");
        expect(texture.width ?? 0).toBeLessThanOrEqual(16384);
      }
      const audio = await all("audio");
      expect(audio.audio.filter(({ format }) => format === "unknown")).toEqual(
        [],
      );
      const resources = await all("resources");
      for (const row of resources.resources) {
        if (
          row.kind === "sound" &&
          row.fields["audio_group"] === 0 &&
          Number(row.fields["audio_file"]) >= 0
        )
          expect(Number(row.fields["audio_file"])).toBeLessThan(
            audio.summary.audio,
          );
        if (row.kind === "sprite")
          expect(Number(row.fields["width"])).toBeLessThanOrEqual(16384);
      }
      expect(createHash("sha256").update(path).digest("hex")).toHaveLength(64);
    },
    120_000,
  );
});
