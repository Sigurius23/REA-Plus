import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { deflateSync } from "node:zlib";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGameArchiveService } from "../../../../src/composition/gameArchives.js";
import type { GameArchive } from "../../../../src/domain/gamearchives/gameArchive.js";
import {
  createDoomWad,
  createGodotPack,
  createRenpyArchive,
  createValveVpk,
  DOOM_LUMPS,
  embedInExecutable,
  GAME_FILES,
  md5,
  sha256,
} from "../../../fixtures/gameArchiveFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createGameArchiveService();
let root = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-game-archives-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const save = async (name: string, bytes: Buffer) => {
  const path = join(root, name);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bytes);
  return path;
};

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as GameArchive;
};

const file = (path: string) =>
  GAME_FILES.find((candidate) => candidate.path === path)?.data ??
  Buffer.alloc(0);

describe("Godot packs", () => {
  it.each([
    [1, [3, 6, 0]],
    [2, [4, 3, 0]],
    [3, [4, 5, 1]],
  ] as const)(
    "lists format %i and verifies stored MD5s",
    async (version, engine) => {
      const path = await save(
        `v${String(version)}.pck`,
        createGodotPack({ version, engine, recordMd5: version !== 1 }),
      );
      const report = await inspect({ path });
      expect(report.archive).toMatchObject({
        format: "godot_pck",
        version: String(version),
        engine_version: engine.join("."),
        embedded_at: null,
        entries: GAME_FILES.length,
      });
      expect(report.entries.map(({ path: entry }) => entry)).toEqual(
        GAME_FILES.map(({ path: entry }) => entry),
      );
      for (const entry of report.entries)
        expect(entry.checksum).toEqual(
          version === 1
            ? null
            : {
                algorithm: "md5",
                value: md5(file(entry.path)),
                verified: true,
              },
        );
    },
  );

  it("reports removals, encrypted files and encrypted directories", async () => {
    const patch = await inspect({
      path: await save(
        "patch.pck",
        createGodotPack({
          version: 3,
          engine: [4, 5, 1],
          encryptedPaths: ["scenes/main.gd"],
          removedPaths: ["old/gone.txt"],
        }),
      ),
      entry: "scenes/main.gd",
    });
    expect(patch.archive.flags).toEqual(["relative_file_base"]);
    expect(patch.entries[0]).toMatchObject({
      path: "scenes/main.gd",
      encrypted: true,
      checksum: { verified: null },
    });
    expect(patch.entries.at(-1)).toMatchObject({
      path: "old/gone.txt",
      removed: true,
      offset: null,
    });
    expect(patch.entry).toMatchObject({
      available: false,
      reason: "The entry is encrypted.",
    });
    const sealed = await inspect({
      path: await save(
        "sealed.pck",
        createGodotPack({
          version: 2,
          engine: [4, 3, 0],
          encryptedDirectory: true,
        }),
      ),
    });
    expect(sealed.archive).toMatchObject({
      flags: ["directory_encrypted"],
      entries: 0,
      notes: [
        expect.stringContaining(
          `${String(GAME_FILES.length)} entries is AES-encrypted`,
        ),
      ],
    });
  });

  it("finds a pack embedded in an exported executable", async () => {
    const pack = createGodotPack({ version: 3, engine: [4, 5, 1] });
    const executable = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      Buffer.alloc(997, 0x90),
    ]);
    const path = await save("Game.x86_64", embedInExecutable(pack, executable));
    const report = await inspect({ path, entry: "scenes/main.gd" });
    expect(report.archive.embedded_at).toBe(1008);
    expect(report.entry).toEqual({
      path: "scenes/main.gd",
      size: file("scenes/main.gd").length,
      available: true,
      reason: null,
      sha256: sha256(file("scenes/main.gd")),
      checksum_verified: true,
      encoding: "utf8",
      preview: file("scenes/main.gd").toString("utf8"),
      truncated: false,
    });
  });

  it("previews binary entries as hex and filters by extension", async () => {
    const path = await save(
      "filter.pck",
      createGodotPack({ version: 2, engine: [4, 4, 1] }),
    );
    const binary = await inspect({
      path,
      entry: "project.binary",
      preview_bytes: 4,
    });
    expect(binary.entry).toMatchObject({
      encoding: "hex",
      preview: "45434647",
      truncated: true,
    });
    const json = await inspect({ path, extension: "JSON" });
    expect(json.entries.map(({ path: entry }) => entry)).toEqual([
      "data/levels.json",
    ]);
    const paged = await inspect({ path, query: "data/", offset: 1, limit: 1 });
    expect(paged.page).toMatchObject({ total: 2, returned: 1 });
  });
});

describe("Ren'Py archives", () => {
  it("rebuilds entries from XORed offsets and index prefixes", async () => {
    const files = GAME_FILES.map((entry, index) => ({
      ...entry,
      prefix: index === 1 ? 4 : 0,
    }));
    const path = await save(
      "game/archive.rpa",
      createRenpyArchive({ version: "3.0", files }),
    );
    const report = await inspect({ path });
    expect(report.archive).toMatchObject({
      format: "renpy_rpa",
      version: "3.0",
      flags: ["xor_obfuscated_index"],
    });
    expect(
      report.entries.map(({ path: entry, size, inline_bytes }) => [
        entry,
        size,
        inline_bytes,
      ]),
    ).toEqual(
      GAME_FILES.map(({ path: entry, data }, index) => [
        entry,
        data.length,
        index === 1 ? 4 : 0,
      ]),
    );
    for (const { path: entry, data } of GAME_FILES) {
      const one = await inspect({ path, entry, limit: 1 });
      expect(one.entry?.sha256).toBe(sha256(data));
    }
  });

  it("reads unkeyed RPA-2.0 archives", async () => {
    const report = await inspect({
      path: await save("old.rpa", createRenpyArchive({ version: "2.0" })),
      entry: "data/levels.json",
    });
    expect(report.archive).toMatchObject({ version: "2.0", flags: [] });
    expect(report.entry?.preview).toBe(
      file("data/levels.json").toString("utf8"),
    );
  });

  it("refuses an index pickle that would run code", async () => {
    const evil = Buffer.from(
      "800263706f7369780a73797374656d0a7100580a0000006563686f2070776e656471018571025271032e",
      "hex",
    );
    const index = deflateSync(evil);
    const bytes = Buffer.concat([
      Buffer.from(`RPA-3.0 ${(34).toString(16).padStart(16, "0")} 00000000\n`),
      index,
    ]);
    expect(
      await service.inspect({ path: await save("evil.rpa", bytes) }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          { message: expect.stringMatching(/refusing global posix\.system/u) },
        ],
      },
    });
  });
});

describe("Valve VPK directories", () => {
  it.each([1, 2] as const)(
    "lists VPK %i with preload data and sibling chunks",
    async (version) => {
      const vpk = createValveVpk({
        version,
        files: [
          {
            path: "materials/hero.vmt",
            data: Buffer.from('"VertexLitGeneric" {}\n'),
          },
          {
            path: "materials/hero.vtf",
            data: Buffer.alloc(3000, 0x33),
            preload: 16,
            archive: 0,
          },
          { path: "root.cfg", data: Buffer.from("sv_cheats 0\n") },
          {
            path: "maps/README",
            data: Buffer.from("no extension\n"),
            preload: 13,
          },
        ],
      });
      const path = await save(`pak0${String(version)}_dir.vpk`, vpk.directory);
      const report = await inspect({ path, entry: "materials/hero.vtf" });
      expect(report.archive).toMatchObject({
        format: "valve_vpk",
        version: String(version),
        flags: ["multi_chunk"],
      });
      const byPath = new Map(
        report.entries.map((entry) => [entry.path, entry]),
      );
      expect(byPath.get("materials/hero.vmt")?.checksum).toMatchObject({
        algorithm: "crc32",
        verified: true,
      });
      expect(byPath.get("root.cfg")?.checksum?.verified).toBe(true);
      expect(byPath.get("maps/README")).toMatchObject({
        inline_bytes: 13,
        offset: null,
        checksum: { verified: true },
      });
      expect(byPath.get("materials/hero.vtf")).toMatchObject({
        stored_in: `pak0${String(version)}_000.vpk`,
        inline_bytes: 16,
        checksum: { verified: null },
      });
      expect(report.entry).toMatchObject({
        available: false,
        reason: `The data is in sibling archive pak0${String(version)}_000.vpk.`,
      });
    },
  );
});

describe("Doom WADs", () => {
  it("groups map lumps, UDMF maps and namespaces", async () => {
    const path = await save("mod.wad", createDoomWad("PWAD", DOOM_LUMPS));
    const report = await inspect({ path, limit: 100, entry: "MAP02/TEXTMAP" });
    expect(report.archive).toMatchObject({
      format: "doom_wad",
      version: "PWAD",
      entries: DOOM_LUMPS.length,
      notes: ["2 map(s); map lumps are listed as MAPNAME/LUMP."],
    });
    expect(
      report.entries.map(({ path: entry, group }) => [entry, group]),
    ).toEqual([
      ["PLAYPAL", null],
      ["MAP01", "map"],
      ["MAP01/THINGS", "MAP01"],
      ["MAP01/LINEDEFS", "MAP01"],
      ["MAP01/SIDEDEFS", "MAP01"],
      ["MAP01/VERTEXES", "MAP01"],
      ["MAP01/SECTORS", "MAP01"],
      ["MAP02", "map"],
      ["MAP02/TEXTMAP", "MAP02"],
      ["MAP02/ZNODES", "MAP02"],
      ["MAP02/ENDMAP", "MAP02"],
      ["S_START", "marker"],
      ["S1_START", "marker"],
      ["sprites/TROOA1", "sprites"],
      ["S1_END", "marker"],
      ["sprites/TROOB1", "sprites"],
      ["S_END", "marker"],
      ["DEHACKED", null],
      ["DEHACKED#2", null],
    ]);
    expect(report.entry?.preview).toContain('namespace = "zdoom"');
  });
});

describe("rejections", () => {
  it("rejects files that are not game archives", async () => {
    const path = await save(
      "notes.txt",
      Buffer.from("PK\u0003\u0004 not a supported archive"),
    );
    expect(await service.inspect({ path })).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [
          {
            path: ["path"],
            message: expect.stringContaining("Not a readable game archive"),
          },
        ],
      },
    });
  });

  it("rejects truncated directories and unknown entries", async () => {
    const pack = createGodotPack({ version: 2, engine: [4, 3, 0] });
    expect(
      await service.inspect({
        path: await save("cut.pck", pack.subarray(0, 120)),
      }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    expect(
      await service.inspect({
        path: await save("ok.pck", pack),
        entry: "missing.gd",
      }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ path: ["entry"] }] },
    });
  });
});

/** A Godot 4.x editor binary (official build), used to pack and list a real archive. */
const GODOT = process.env["REA_VERIFY_GODOT_BIN"];
/** The Freedoom 0.13.0 release directory holding freedoom1.wad and freedoom2.wad. */
const FREEDOOM = process.env["REA_VERIFY_FREEDOOM_DIR"];

const PACK_SCRIPT = `extends SceneTree
func _init():
\tvar args = OS.get_cmdline_user_args()
\tvar packer = PCKPacker.new()
\tpacker.pck_start(args[0], 32)
\tfor rel in args.slice(2):
\t\tpacker.add_file("res://" + rel, args[1] + "/" + rel)
\tpacker.flush(false)
\tquit()
`;

const LIST_SCRIPT = `extends SceneTree
func walk(dir_path):
\tvar dir = DirAccess.open(dir_path)
\tfor f in dir.get_files():
\t\tvar p = dir_path.path_join(f)
\t\tif p != "res://project.godot":
\t\t\tprint("FILE\\t", p.trim_prefix("res://"), "\\t", FileAccess.get_file_as_bytes(p).size(), "\\t", FileAccess.get_md5(p))
\tfor d in dir.get_directories():
\t\twalk(dir_path.path_join(d))
func _init():
\tProjectSettings.load_resource_pack(OS.get_cmdline_user_args()[0])
\twalk("res://")
\tquit()
`;

describe.skipIf(GODOT === undefined)("real Godot packs", () => {
  it("matches what the engine packs and loads", async () => {
    const run = promisify(execFile);
    const work = join(root, "godot");
    const project = join(work, "project");
    const sources = join(work, "sources");
    await mkdir(project, { recursive: true });
    await writeFile(
      join(project, "project.godot"),
      'config_version=5\n\n[application]\nconfig/name="rea"\n',
    );
    await writeFile(join(work, "pack.gd"), PACK_SCRIPT);
    await writeFile(join(work, "list.gd"), LIST_SCRIPT);
    for (const { path, data } of GAME_FILES)
      await save(join("godot", "sources", path), data);
    const pack = join(work, "real.pck");
    const godot = (script: string, args: readonly string[]) =>
      run(
        GODOT ?? "",
        [
          "--headless",
          "--path",
          project,
          "--script",
          join(work, script),
          "--",
          ...args,
        ],
        {
          env: { ...process.env, HOME: work },
          timeout: 120_000,
        },
      );
    await godot("pack.gd", [
      pack,
      sources,
      ...GAME_FILES.map(({ path }) => path),
    ]);
    const { stdout } = await godot("list.gd", [pack]);
    const engine = stdout
      .split("\n")
      .filter((line) => line.startsWith("FILE\t"))
      .map((line) => line.split("\t"))
      .map(([, path, size, hash]) => [path, Number(size), hash])
      .sort();
    expect(engine).toHaveLength(GAME_FILES.length);
    const report = await inspect({ path: pack });
    expect(
      report.entries
        .map(({ path, size, checksum }) => [
          path,
          size,
          checksum?.verified === true ? checksum.value : null,
        ])
        .sort(),
    ).toEqual(engine);
  });
});

describe.skipIf(FREEDOOM === undefined)("real Freedoom WADs", () => {
  const data = FREEDOOM ?? "";
  it.each([
    {
      name: "freedoom1.wad",
      lumps: 3163,
      maps: 36,
      firstMap: "E1M1",
      lump: "E1M1/THINGS",
      hash: "9200fe55b6b49e15cafbd01dbca6bc0a1ffd2715ff5e3f49bddb01c142b5a720",
    },
    {
      name: "freedoom2.wad",
      lumps: 3610,
      maps: 32,
      firstMap: "MAP01",
      lump: "MAP01/LINEDEFS",
      hash: "7092553232fa51bd95440eee5cf0a47d5ffd509a6eaeb61ed7d2c57195b1631d",
    },
  ])(
    "$name matches omgifol 0.5.1",
    async ({ name, lumps, maps, firstMap, lump, hash }) => {
      const report = await inspect({
        path: join(data, name),
        limit: 1000,
        entry: lump,
      });
      expect(report.archive).toMatchObject({
        version: "IWAD",
        entries: lumps,
        notes: [
          `${String(maps)} map(s); map lumps are listed as MAPNAME/LUMP.`,
        ],
      });
      const mapNames = (
        await inspect({ path: join(data, name), query: firstMap, limit: 1 })
      ).entries;
      expect(mapNames[0]).toMatchObject({ path: firstMap, group: "map" });
      expect(report.entry?.sha256).toBe(hash);
      const flats = await inspect({
        path: join(data, name),
        query: "flats/",
        limit: 1,
      });
      expect(flats.page.total).toBe(240);
    },
  );
});
