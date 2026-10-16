import { readdirSync } from "node:fs";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { extname, join, normalize, sep } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createRpgMakerProjectService } from "../../../../src/composition/rpgMaker.js";
import type { RpgMakerProjectReport } from "../../../../src/domain/rpgmaker/rpgMakerProject.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/**
 * Real lane: each folder under REA_VERIFY_RPGMAKER_GAMES is a deployed MV
 * (www/ contents) or MZ game. The game's own engine runs in Chromium
 * (REA_VERIFY_CHROMIUM); its decryption and its saves are compared with REA+.
 */
const GAMES = process.env["REA_VERIFY_RPGMAKER_GAMES"];
const CHROMIUM = process.env["REA_VERIFY_CHROMIUM"];
const names =
  GAMES === undefined
    ? []
    : readdirSync(GAMES, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map(({ name }) => name);

const service = createRpgMakerProjectService();
let root = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-rpgmaker-engine-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as RpgMakerProjectReport;
};

const TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
};

/** Serve one folder read-only on loopback, as the engine expects an origin. */
const serve = async (folder: string): Promise<{ server: Server; url: string }> => {
  const server = createServer((request, response) => {
    const path = normalize(decodeURIComponent((request.url ?? "/").split("?")[0] ?? "/"));
    const file = join(folder, path === `${sep}` ? "index.html" : path);
    if (!file.startsWith(folder + sep)) {
      response.writeHead(403).end();
      return;
    }
    readFile(file).then(
      (body) => {
        response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
        response.end(body);
      },
      () => response.writeHead(404).end(),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return { server, url: `http://127.0.0.1:${String(port)}/` };
};

interface EngineFacts {
  readonly name: string;
  readonly key: string | null;
  readonly maps: { id: number; name: string }[];
  readonly assets: Record<string, { sha256: string; width: number | null; height: number | null }>;
  readonly save: {
    file: string;
    global: string;
    gold: number;
    party: number[];
    items: Record<string, number>;
    mapId: number;
    x: number;
    y: number;
    versionId: number;
    frames: number;
    timestamp: number;
  };
}

/** Everything the engine itself decides, read from the running game. */
const engineFacts = async (url: string, assets: readonly string[]): Promise<EngineFacts> => {
  const { chromium } = await import("playwright-core");
  const browser = await chromium.launch({ executablePath: CHROMIUM ?? "", args: ["--mute-audio"] });
  try {
    const page = await browser.newPage();
    await page.goto(`${url}index.html`, { waitUntil: "load", timeout: 120_000 });
    // Passive check: calling isReady() would make the engine raise its own load errors here.
    await page.waitForFunction(
      () => {
        const scene = SceneManager._scene;
        return (
          DataManager.isDatabaseLoaded() &&
          scene !== null &&
          scene.constructor.name !== "Scene_Boot" &&
          (scene._started === true || scene._active === true)
        );
      },
      null,
      { timeout: 180_000 },
    );
    return await page.evaluate(engineScript, assets);
  } finally {
    await browser.close();
  }
};

declare const SceneManager: { _scene: { constructor: { name: string }; _started?: boolean; _active?: boolean } | null };
declare const DataManager: { isDatabaseLoaded(): boolean };

/** Runs inside the game page: decrypt with the engine, then start a game and save it. */
const engineScript = async (assets: readonly string[]): Promise<EngineFacts> => {
  const g = globalThis as unknown as Record<string, any>;
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const hex = (buffer: ArrayBuffer) => [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const mz = g.Utils.RPGMAKER_NAME === "MZ";
  const decrypted: EngineFacts["assets"] = {};
  for (const asset of assets) {
    const source = await (await fetch(asset)).arrayBuffer();
    const plain: ArrayBuffer = mz ? g.Utils.decryptArrayBuffer(source) : g.Decrypter.decryptArrayBuffer(source);
    let size: { width: number | null; height: number | null } = { width: null, height: null };
    try {
      const bitmap = await g.createImageBitmap(new Blob([plain]));
      size = { width: bitmap.width, height: bitmap.height };
    } catch {}
    decrypted[asset] = { sha256: hex(await crypto.subtle.digest("SHA-256", plain)), ...size };
  }
  const maps = g.$dataMapInfos.filter(Boolean).map(({ id, name }: { id: number; name: string }) => ({ id, name }));
  // Plugins with a pre-title map (Scene_PretitleMap) boot past the title; save from there.
  if (g.SceneManager._scene.constructor.name === "Scene_Title") {
    g.DataManager.setupNewGame();
    g.SceneManager.goto(g.Scene_Map);
  }
  const settled = () =>
    g.$dataMap !== null && g.SceneManager._scene?._active === true && !g.SceneManager.isSceneChanging();
  for (let tick = 0; tick < 300 && !settled(); tick += 1) await sleep(100);
  g.$gameParty.gainGold(1234);
  const item = g.$dataItems.find((entry: unknown) => entry !== null);
  if (item !== undefined) g.$gameParty.gainItem(item, 3);
  g.$gameSwitches.setValue(1, true);
  g.$gameVariables.setValue(1, 42);
  g.$gameVariables.setValue(2, "text value");
  g.$gameSystem.onBeforeSave();
  let file: string;
  let global: string;
  if (mz) {
    await g.DataManager.saveGame(1);
    for (let tick = 0; tick < 50; tick += 1) {
      const info = await g.localforage.getItem(g.StorageManager.forageKey("global"));
      if (info !== null) break;
      await sleep(100);
    }
    file = await g.localforage.getItem(g.StorageManager.forageKey("file1"));
    global = await g.localforage.getItem(g.StorageManager.forageKey("global"));
  } else {
    g.DataManager.saveGame(1);
    file = g.localStorage.getItem(g.StorageManager.webStorageKey(1));
    global = g.localStorage.getItem(g.StorageManager.webStorageKey(0));
  }
  const info = mz ? g.DataManager._globalInfo[1] : g.DataManager.loadGlobalInfo()[1];
  return {
    name: g.Utils.RPGMAKER_NAME,
    key: g.$dataSystem.encryptionKey ?? null,
    maps,
    assets: decrypted,
    save: {
      file,
      global,
      gold: g.$gameParty.gold(),
      party: [...g.$gameParty._actors],
      items: { ...g.$gameParty._items },
      mapId: g.$gameMap.mapId(),
      x: g.$gamePlayer.x,
      y: g.$gamePlayer.y,
      versionId: g.$gameSystem._versionId,
      frames: g.$gameSystem._framesOnSave,
      timestamp: info.timestamp,
    },
  };
};

describe.skipIf(GAMES === undefined || CHROMIUM === undefined)("real RPG Maker games run by their own engine", () => {
  it.each(names)("matches the engine for %s", async (name) => {
    const game = join(root, name);
    await cp(join(GAMES ?? "", name), game, { recursive: true });
    const overview = await inspect({ path: game, view: "assets", limit: 1000 });
    const www = overview.project.layout === "deployed-www";
    const base = www ? join(game, "www") : game;
    const served = (path: string) => (www ? path.replace(/^www\//u, "") : path);
    const encrypted = overview.assets.filter(({ encrypted, header }) => encrypted && header === "valid").slice(0, 6);
    if (overview.encryption.images) expect(encrypted.length).toBeGreaterThan(0);
    const { server, url } = await serve(base);
    const facts = await engineFacts(url, encrypted.map(({ path }) => served(path))).finally(() => server.close());
    expect(overview.project.engine).toBe(facts.name.toLowerCase());
    expect(overview.encryption.key).toBe(facts.key);
    expect(overview.encryption.key_matches).not.toBe(false);
    const maps = await inspect({ path: game, view: "maps", limit: 1000 });
    expect(maps.maps.map(({ id, name: map }) => ({ id, name: map }))).toEqual(facts.maps);
    for (const asset of encrypted) {
      const [selected] = (await inspect({ path: game, view: "assets", asset: asset.path })).assets;
      const engine = facts.assets[served(asset.path)];
      expect(selected?.sha256, asset.path).toBe(engine?.sha256);
      if (engine?.width !== null && selected?.image !== null)
        expect(selected?.image).toEqual({ width: engine?.width, height: engine?.height });
    }
    const mz = facts.name === "MZ";
    const extension = mz ? "rmmzsave" : "rpgsave";
    await mkdir(join(base, "save"), { recursive: true });
    await writeFile(join(base, "save", `file1.${extension}`), facts.save.file, "utf8");
    await writeFile(join(base, "save", `global.${extension}`), facts.save.global, "utf8");
    const saves = await inspect({ path: game, view: "saves" });
    const save = saves.saves.find(({ kind }) => kind === "game");
    expect(save).toMatchObject({
      slot: 1,
      gold: facts.save.gold,
      version_id: facts.save.versionId,
      playtime_seconds: Math.floor(facts.save.frames / 60),
      saved_at: new Date(facts.save.timestamp).toISOString(),
      map: { id: facts.save.mapId, x: facts.save.x, y: facts.save.y },
    });
    expect(save?.party.map(({ actor_id }) => actor_id)).toEqual(facts.save.party);
    expect(save?.items.filter(({ kind }) => kind === "item").map(({ id, count }) => [String(id), count])).toEqual(Object.entries(facts.save.items));
    expect(save?.switches_on.map(({ id }) => id)).toContain(1);
    expect(save?.variables.filter(({ id }) => id <= 2).map(({ value }) => value)).toEqual([42, "text value"]);
  }, 600_000);
});
