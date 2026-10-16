import { createHash } from "node:crypto";
import { rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createRpgMakerProjectService } from "../../../../src/composition/rpgMaker.js";
import type { RpgMakerProjectReport } from "../../../../src/domain/rpgmaker/rpgMakerProject.js";
import {
  createPng,
  createRpgMakerGame,
  FIXTURE_KEY,
} from "../../../fixtures/rpgMakerFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createRpgMakerProjectService();
let root = "";
const games = { mv: "", mz: "" };

beforeAll(async () => {
  root = (await createTestWorkspace("rea-rpgmaker-")).root;
  games.mv = await createRpgMakerGame(join(root, "mv"), "mv");
  games.mz = await createRpgMakerGame(join(root, "mz"), "mz");
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as RpgMakerProjectReport;
};

describe.each(["mv", "mz"] as const)("RPG Maker %s games", (engine) => {
  it("summarises the project, encryption and maps", async () => {
    const report = await inspect({ path: games[engine] });
    expect(report.project).toMatchObject({
      engine,
      layout: engine === "mv" ? "deployed-www" : "root",
      core_version: engine === "mv" ? "1.6.2" : "1.8.0",
      title: "Fixture Quest",
      version_id: 123456,
      start: { map_id: 1, x: 3, y: 4 },
      data_files: 16,
    });
    expect(report.encryption).toEqual({
      images: true,
      audio: true,
      key: FIXTURE_KEY,
      empty_passphrase: false,
      recovered_key: FIXTURE_KEY,
      key_matches: true,
    });
    expect(report.summary).toMatchObject({
      maps: 3,
      events: 3,
      messages: 4,
      choices: 1,
      switches: 3,
      variables: 2,
      plugins: { total: 2, enabled: 1, missing: 1 },
      assets: { encrypted: 3, plain: 1, undecryptable: 1 },
      saves: 3,
    });
    expect(report.maps.map(({ id, present, messages, transfers, common_events }) => [id, present, messages, transfers, common_events])).toEqual([
      [1, true, 2, [2], [1]],
      [2, true, 0, [], []],
      [3, false, 0, [], []],
    ]);
    expect(report.maps[1]).toMatchObject({ name: "Cave", parent_id: 1, display_name: null });
  });

  it("lists dialogue with speakers, faces and choices", async () => {
    const report = await inspect({ path: games[engine], view: "dialogue" });
    expect(report.dialogue.map(({ source, event_name, page, index, kind, lines }) => [source, event_name, page, index, kind, lines])).toEqual([
      ["map", "Elder", 1, 0, "message", ["Welcome, \\N[1]!", "The cave is \\C[2]north\\C[0]."]],
      ["map", "Elder", 1, 3, "choice", ["Go to the cave", "Stay"]],
      ["map", "Elder", 2, 0, "scrolling", ["Credits line 1", "Credits line 2"]],
      ["map", "Elder", 2, 3, "comment", ["<quest:start>", "second comment line"]],
      ["map", "Sign", 1, 1, "message", ["The boss is gone."]],
      ["common_event", null, null, 0, "message", ["You feel rested."]],
      ["troop", null, 1, 0, "message", ["The slimes wobble."]],
    ]);
    expect(report.dialogue[0]).toMatchObject({
      source_name: "Village",
      speaker: engine === "mz" ? "Elder" : null,
      face: "Actor1:2",
    });
    const cave = await inspect({ path: games[engine], view: "dialogue", map: 2 });
    expect(cave.dialogue).toEqual([]);
    const query = await inspect({ path: games[engine], view: "dialogue", query: "SLIMES" });
    expect(query.page).toMatchObject({ total: 1, returned: 1 });
  });

  it("maps switch and variable reads and writes", async () => {
    const report = await inspect({ path: games[engine], view: "switches" });
    const rows = report.switches.map(({ kind, id, name, reads, writes }) => [kind, id, name, reads, writes]);
    expect(rows).toEqual([
      ["switch", 1, "door_open", 1, 1],
      ["switch", 3, "boss_beaten", 2, 0],
      ["switch", 4, "timer_on", 1, 0],
      ["variable", 1, "gold_found", 0, 1],
      ["variable", 2, "steps_left", 2, 0],
      ["variable", 3, "", 1, 0],
      ["variable", 4, "", 1, 0],
      ["variable", 5, "", 1, 0],
    ]);
    expect(report.switches[0]?.sites).toEqual([
      expect.objectContaining({ event_name: "Elder", page: 1, index: 5, access: "write", command: 121 }),
      expect.objectContaining({ event_name: "Elder", page: 2, access: "read", command: null }),
    ]);
    const cave = await inspect({ path: games[engine], view: "switches", map: 2 });
    expect(cave.switches.map(({ id }) => id)).toEqual([3, 4, 5]);
  });

});

describe.each(["mv", "mz"] as const)("RPG Maker %s game files", (engine) => {
  const prefix = engine === "mv" ? "www/" : "";
  const image = engine === "mv" ? ".rpgmvp" : ".png_";

  it("lists the database, plugins and assets", async () => {
    const items = await inspect({ path: games[engine], view: "database", table: "items" });
    expect(items.database).toEqual([
      expect.objectContaining({ id: 1, name: "Potion", fields: { price: 50, iconIndex: 176 } }),
      expect.objectContaining({ id: 2, name: "Cave Key", notetags: ["Key Item"] }),
    ]);
    const actors = await inspect({ path: games[engine], view: "database", query: "hero" });
    expect(actors.database[0]).toMatchObject({ table: "actors", notetags: ["Biography", "HP Regen"] });
    const plugins = await inspect({ path: games[engine], view: "plugins" });
    expect(plugins.plugins).toEqual([
      {
        name: "FixturePlugin",
        status: true,
        description: "Adds things",
        parameters: { Speed: "4", List: '["a"]' },
        file: `${prefix}js/plugins/FixturePlugin.js`,
        present: true,
        bytes: 17,
        sha256: createHash("sha256").update("// FixturePlugin\n").digest("hex"),
      },
      expect.objectContaining({ name: "MissingPlugin", present: false, sha256: null }),
    ]);
    const assets = await inspect({ path: games[engine], view: "assets" });
    expect(assets.assets.map(({ path, encrypted, header, signature }) => [path, encrypted, header, signature])).toEqual([
      [`${prefix}img/faces/Actor1${image}`, true, "valid", "png"],
      [`${prefix}img/pictures/broken${image}`, true, "invalid", "unknown"],
      [`${prefix}img/system/Window.png`, false, null, "png"],
      [`${prefix}audio/se/Cursor1${engine === "mv" ? ".rpgmvo" : ".ogg_"}`, true, "valid", "ogg"],
    ]);
    const face = await inspect({ path: games[engine], view: "assets", asset: `${prefix}img/faces/Actor1${image}` });
    expect(face.assets).toEqual([
      expect.objectContaining({
        decrypted_path: `${prefix}img/faces/Actor1.png`,
        sha256: createHash("sha256").update(createPng(4, 2)).digest("hex"),
        image: { width: 4, height: 2 },
      }),
    ]);
  });

  it("decodes saves with names from the database", async () => {
    const report = await inspect({ path: games[engine], view: "saves" });
    const save = engine === "mv" ? "rpgsave" : "rmmzsave";
    expect(report.saves.map(({ path, kind, slot }) => [path, kind, slot])).toEqual([
      [`${prefix}save/config.${save}`, "config", null],
      [`${prefix}save/file1.${save}`, "game", 1],
      [`${prefix}save/global.${save}`, "global", null],
    ]);
    expect(report.saves[1]).toMatchObject({
      format: engine === "mv" ? "lz-string" : "zlib",
      version_id: 123456,
      saved_at: "2026-01-01T00:00:00.000Z",
      playtime_seconds: 3661,
      map: { id: 2, name: "Cave", x: 10, y: 12 },
      gold: 999,
      steps: 42,
      party: [{ actor_id: 1, name: "Hero", level: 5, hp: 120, mp: 30 }],
      items: [
        { kind: "item", id: 1, name: "Potion", count: 3 },
        { kind: "item", id: 2, name: "Cave Key", count: 1 },
        { kind: "weapon", id: 1, name: "Sword", count: 1 },
      ],
      switches_on: [
        { id: 1, name: "door_open" },
        { id: 3, name: "boss_beaten" },
      ],
      variables: [
        { id: 1, name: "gold_found", value: 7 },
        { id: 3, name: null, value: "north" },
      ],
      self_switches_on: 1,
    });
    expect(report.saves[0]?.keys).toEqual(["alwaysDash"]);
  });
});

describe("RPG Maker refusals", () => {
  it("refuses folders that are not MV/MZ games and unsafe asset paths", async () => {
    expect(await service.inspect({ path: root })).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [{ message: expect.stringContaining("Not a readable RPG Maker MV/MZ game") }],
      },
    });
    for (const asset of ["../mz/img/faces/Actor1.png_", "/etc/passwd"])
      expect(await service.inspect({ path: games.mz, view: "assets", asset })).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError", issues: [{ path: ["asset"] }] },
      });
    expect(await service.inspect({ path: games.mz, view: "assets", asset: "img/none.png" })).toMatchObject({
      ok: false,
      error: { issues: [{ message: expect.stringContaining("No image, audio or movie file") }] },
    });
  });

  it("refuses symlinked data and never runs plugins.js", async () => {
    const game = await createRpgMakerGame(join(root, "hostile"), "mz");
    await writeFile(
      join(game, "js", "plugins.js"),
      'var $plugins = [require("child_process").execSync("touch pwned")];\n',
    );
    const report = await inspect({ path: game, view: "plugins" });
    expect(report.plugins).toEqual([]);
    expect(report.limitations).toContain("js/plugins.js is not the editor's JSON plugin list");
    await rm(join(game, "data", "Map002.json"));
    await symlink(join(game, "data", "Map001.json"), join(game, "data", "Map002.json"));
    expect(await service.inspect({ path: game })).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ message: expect.stringContaining("symlink") }] },
    });
  });
});
