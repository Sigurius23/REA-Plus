import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createUnityAssetsService } from "../../../../src/composition/unity.js";
import type { UnityAssets } from "../../../../src/domain/unity/unityAssets.js";
import {
  BUNDLE_FILE as B,
  createBundleSerializedFile,
  createHeroBundle,
  createPlayerSerializedFile,
  createUnityFsBundle,
  PLAYER_FILE as P,
} from "../../../fixtures/unityFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createUnityAssetsService();
let root = "";
let player = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-unity-")).root;
  player = join(root, P.name);
  await writeFile(player, createPlayerSerializedFile());
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as UnityAssets;
};

const writeBundle = async (name: string, bytes: Buffer) => {
  const path = join(root, name);
  await writeFile(path, bytes);
  return path;
};

describe("player serialized files without type trees", () => {
  it("names objects, owners and scripts from known layouts", async () => {
    const report = await inspect({ path: player });
    expect(report.file).toMatchObject({ format: "serialized_file" });
    expect(report.bundle).toBeNull();
    expect(report.serialized_files).toMatchObject([
      {
        name: P.name,
        format_version: 22,
        unity_version: P.unityVersion,
        target_platform: { id: 19, name: "StandaloneWindows64" },
        type_tree: false,
        objects: 8,
        externals: [
          { file_id: 1, path: "globalgamemanagers.assets" },
          {
            file_id: 2,
            path: "Library/unity default resources",
            guid: "0000000000000000e000000000000000",
          },
        ],
        script_references: 1,
        names: { read: 7, unread: 1, failed: 0 },
      },
    ]);
    const byId = new Map(report.objects.map((row) => [row.path_id, row]));
    const owner = { path_id: String(P.player), name: "Player" };
    expect(byId.get(String(P.player))).toMatchObject({
      class_name: "GameObject",
      name: "Player",
      game_object: null,
    });
    expect(byId.get(String(P.transform))).toMatchObject({
      class_name: "Transform",
      name: null,
      game_object: owner,
    });
    expect(byId.get(String(P.controller))).toMatchObject({
      game_object: owner,
      script: {
        file_id: 0,
        file: null,
        class_name: "PlayerController",
        namespace: "Game.Characters",
        assembly: "Assembly-CSharp.dll",
      },
    });
    expect(byId.get(String(P.spawner))).toMatchObject({
      name: "Spawner",
      script: {
        file_id: 1,
        path_id: String(P.externalScript),
        file: "globalgamemanagers.assets",
        class_name: null,
      },
    });
    expect(byId.get(String(P.settings))).toMatchObject({
      class_name: "RenderSettings",
      name: null,
    });
  });

  it("lists Resources.Load paths and scripts as separate views", async () => {
    const container = await inspect({ path: player, view: "container" });
    expect(container.container).toMatchObject([
      {
        source: "resource_manager",
        asset_path: "textures/hero",
        class_name: "Texture2D",
        name: "hero_diffuse",
      },
      { asset_path: "scripts/player", class_name: "MonoScript" },
      {
        asset_path: "ui/atlas",
        file_id: 2,
        target_file: "Library/unity default resources",
        class_name: null,
      },
    ]);
    expect(container.objects).toEqual([]);
    const scripts = await inspect({ path: player, view: "scripts" });
    expect(scripts.scripts).toEqual([
      {
        file: P.name,
        path_id: String(P.script),
        local: true,
        class_name: "PlayerController",
        namespace: "Game.Characters",
        assembly: "Assembly-CSharp.dll",
        behaviours: 1,
      },
      {
        file: "globalgamemanagers.assets",
        path_id: String(P.externalScript),
        local: false,
        class_name: null,
        namespace: null,
        assembly: null,
        behaviours: 1,
      },
    ]);
  });

  it("filters by class and query, and pages", async () => {
    const behaviours = await inspect({
      path: player,
      class_name: "monobehaviour",
    });
    expect(behaviours.objects.map(({ path_id }) => path_id)).toEqual([
      String(P.controller),
      String(P.spawner),
    ]);
    const query = await inspect({ path: player, query: "playercontroller" });
    expect(query.objects.map(({ path_id }) => path_id)).toEqual([
      String(P.controller),
      String(P.script),
    ]);
    const paged = await inspect({ path: player, offset: 6, limit: 5 });
    expect(paged.page).toMatchObject({ total: 8, returned: 2 });
  });
});

describe("UnityFS bundles with type trees", () => {
  it.each([
    ["uncompressed format 7", createHeroBundle("none")],
    ["uncompressed format 6", createHeroBundle("none", { formatVersion: 6 })],
    ["multi-block LZ4", createHeroBundle("lz4", { blockSize: 100 })],
    [
      "LZMA with the block table last",
      createHeroBundle("lzma", { atEnd: true }),
    ],
    [
      "LZ4 format 6 with the block table last",
      createHeroBundle("lz4", { atEnd: true, formatVersion: 6, blockSize: 64 }),
    ],
    [
      "a big-endian serialized file",
      createUnityFsBundle({
        compression: "none",
        nodes: [
          { path: B.name, data: createBundleSerializedFile(false), flags: 4 },
        ],
      }),
    ],
  ])("reads %s", async (name, bytes) => {
    const report = await inspect({
      path: await writeBundle(`${name.replaceAll(" ", "_")}.bundle`, bytes),
    });
    expect(report.file.format).toBe("unityfs");
    expect(report.serialized_files).toMatchObject([
      {
        name: B.name,
        format_version: 17,
        type_tree: true,
        target_platform: { id: 13, name: "Android" },
        names: { read: 5, unread: 0, failed: 0 },
      },
    ]);
    expect(
      report.objects.map((row) => [row.path_id, row.class_name, row.name]),
    ).toEqual([
      [String(B.bundle), "AssetBundle", "characters/hero"],
      [String(B.texture), "Texture2D", "hero"],
      [String(B.hero), "GameObject", "Hero"],
      [String(B.behaviour), "MonoBehaviour", ""],
      [String(B.script), "MonoScript", "HeroController"],
    ]);
    expect(report.objects[3]).toMatchObject({
      game_object: { path_id: String(B.hero), name: "Hero" },
      script: { class_name: "HeroController", namespace: "Game" },
    });
    expect(report.dependencies).toEqual(["shared/shaders"]);
  });

  it("reports blocks, directory nodes and asset paths", async () => {
    const path = await writeBundle(
      "hero.lz4",
      createHeroBundle("lz4", { blockSize: 100 }),
    );
    const report = await inspect({ path, view: "container" });
    expect(report.bundle).toMatchObject({
      format_version: 7,
      unity_revision: B.unityRevision,
      blocks_info: { compression: "lz4hc", at_end: false },
      blocks: { compression: [{ method: "lz4hc" }] },
      nodes: [
        { path: B.name, flags: "0x4", kind: "serialized_file" },
        { path: B.resource, kind: "resource", size: 96 },
      ],
    });
    expect(report.bundle?.blocks.count).toBeGreaterThan(40);
    expect(report.container).toEqual([
      {
        source: "asset_bundle",
        file: B.name,
        asset_path: "assets/characters/hero.prefab",
        file_id: 0,
        path_id: String(B.hero),
        target_file: null,
        class_name: "GameObject",
        name: "Hero",
        preload_index: 0,
        preload_size: 2,
      },
      {
        source: "asset_bundle",
        file: B.name,
        asset_path: "assets/characters/hero.png",
        file_id: 0,
        path_id: String(B.texture),
        target_file: null,
        class_name: "Texture2D",
        name: "hero",
        preload_index: 2,
        preload_size: 1,
      },
    ]);
    const textures = await inspect({
      path,
      view: "container",
      class_name: "Texture2D",
    });
    expect(textures.container.map(({ asset_path }) => asset_path)).toEqual([
      "assets/characters/hero.png",
    ]);
  });
});

describe("rejections", () => {
  const rejects = async (
    input: Record<string, unknown>,
    field: string,
    message: RegExp,
  ) =>
    expect(await service.inspect(input)).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [{ path: [field], message: expect.stringMatching(message) }],
      },
    });

  it("rejects files that are not Unity assets", async () => {
    const text = await writeBundle(
      "notes.txt",
      Buffer.from("v 1 2 3\r\nf 1 2 3\r\n"),
    );
    await rejects({ path: text }, "path", /Not readable Unity asset data/u);
    const web = await writeBundle(
      "old.unity3d",
      Buffer.concat([Buffer.from("UnityWeb\0"), Buffer.alloc(64)]),
    );
    await rejects({ path: web }, "path", /Not readable Unity asset data/u);
  });

  it("rejects truncated and corrupt bundles", async () => {
    const bundle = createHeroBundle("lz4", { blockSize: 100 });
    const truncated = await writeBundle(
      "truncated.bundle",
      bundle.subarray(0, bundle.length - 500),
    );
    await rejects({ path: truncated }, "path", /lies outside|past the end/u);
    const corrupt = Buffer.from(bundle);
    corrupt.fill(0xff, 200, 260);
    const result = await service.inspect({
      path: await writeBundle("corrupt.bundle", corrupt),
    });
    // Damage inside the data blocks is reported per file, not fatal.
    if (result.ok)
      expect(
        (result.value.normalized_result as UnityAssets).serialized_files[0],
      ).toMatchObject({ error: expect.any(String) });
    else expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("rejects class_name on the scripts view", async () => {
    await rejects(
      { path: player, view: "scripts", class_name: "MonoScript" },
      "class_name",
      /objects and container views/u,
    );
  });
});

/** UnityPy's sample bundles (tests/samples in K0lb3/UnityPy, fetched through Git LFS). */
const SAMPLES = process.env["REA_VERIFY_UNITY_SAMPLES_DIR"];
/** `Startup_Data` from Unity ML-Agents' 1.1.0 Linux test build (Unity 2022.3.4f1). */
const PLAYER = process.env["REA_VERIFY_UNITY_PLAYER_DIR"];

describe.skipIf(SAMPLES === undefined)("real UnityPy sample bundles", () => {
  const samples = SAMPLES ?? "";
  it.each([
    [
      "atlas_test",
      10,
      "atlas_buildings_water_tower",
      8,
      "assets/ui/textures/atlases/buildingswatertoweratlas.spriteatlas",
      "-9222691446010724640",
    ],
    [
      "banner_1",
      3,
      "images/banner/banner_1",
      2,
      "assets/assetbundles/images/banner/banner_1.png",
      "-3875358842991402074",
    ],
    [
      "char_118_yuki.ab",
      36,
      "audio/sound_beta_2/voice/char_118_yuki.ab",
      35,
      "assets/torappu/dynamicassets/audio/sound_beta_2/voice/char_118_yuki/cn_001.ogg",
      "-8214014251178022607",
    ],
    [
      "xinzexi_2_n_tex",
      4,
      "painting/xinzexi_2_n_tex",
      3,
      "assets/artresource/atlas/paintings/xinzexi_2_n-mesh.asset",
      "-9097144649164150351",
    ],
  ])(
    "%s matches UnityPy 1.25.4",
    async (name, objects, bundleName, containers, firstPath, firstPathId) => {
      const path = join(samples, name);
      if (!existsSync(path)) throw new Error(`Missing sample ${path}`);
      const report = await inspect({ path, limit: 1000 });
      expect(report.serialized_files).toMatchObject([
        {
          format_version: 17,
          type_tree: true,
          names: { read: objects, failed: 0 },
        },
      ]);
      expect(report.objects).toHaveLength(objects);
      expect(
        report.objects.find(({ class_id }) => class_id === 142)?.name,
      ).toBe(bundleName);
      const container = await inspect({ path, view: "container", limit: 1000 });
      expect(container.container).toHaveLength(containers);
      expect(container.container[0]).toMatchObject({
        asset_path: firstPath,
        path_id: firstPathId,
      });
    },
  );
});

describe.skipIf(PLAYER === undefined)("real Unity 2022.3 player data", () => {
  const data = PLAYER ?? "";
  it("reads a scene without type trees like UnityPy 1.25.4", async () => {
    const report = await inspect({ path: join(data, "level5"), limit: 1000 });
    expect(report.serialized_files[0]).toMatchObject({
      format_version: 22,
      unity_version: "2022.3.4f1",
      target_platform: { id: 24, name: "StandaloneLinux64" },
      type_tree: false,
      objects: 6351,
      names: { failed: 0 },
    });
    expect(report.classes).toEqual(
      expect.arrayContaining([
        { class_id: 1, class_name: "GameObject", objects: 1578 },
        { class_id: 114, class_name: "MonoBehaviour", objects: 295 },
      ]),
    );
    const doors = await inspect({
      path: join(data, "level5"),
      class_name: "GameObject",
      query: "door",
    });
    expect(doors.objects[0]).toMatchObject({ path_id: "3", name: "Door" });
    const behaviours = await inspect({
      path: join(data, "level5"),
      class_name: "MonoBehaviour",
      limit: 1,
    });
    expect(behaviours.objects[0]).toMatchObject({
      path_id: "6057",
      game_object: { path_id: "21" },
      script: { file_id: 1, path_id: "571", file: "globalgamemanagers.assets" },
    });
  });

  it("lists ResourceManager paths and MonoScripts", async () => {
    const resources = await inspect({
      path: join(data, "globalgamemanagers"),
      view: "container",
      limit: 3,
    });
    expect(resources.page.total).toBe(99);
    expect(resources.container[0]).toMatchObject({
      source: "resource_manager",
      asset_path: "sentis/computeshaders/activations",
      file_id: 7,
      path_id: "61",
      target_file: "resources.assets",
    });
    const scripts = await inspect({
      path: join(data, "globalgamemanagers.assets"),
      view: "scripts",
      query: "unity.mlagents",
    });
    expect(scripts.scripts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path_id: "676",
          class_name: "Agent",
          namespace: "Unity.MLAgents",
          assembly: "Unity.ML-Agents",
        }),
        expect.objectContaining({
          path_id: "414",
          class_name: "BehaviorParameters",
          namespace: "Unity.MLAgents.Policies",
        }),
      ]),
    );
    const all = await inspect({
      path: join(data, "globalgamemanagers.assets"),
      view: "scripts",
      limit: 1,
    });
    expect(all.page.total).toBe(1220);
  });
});
