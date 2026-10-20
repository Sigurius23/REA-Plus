import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGodotFileService } from "../../../../src/composition/godot.js";
import type { GodotFileReport } from "../../../../src/domain/godot/godotFile.js";
import {
  createGodotPack,
  embedInExecutable,
} from "../../../fixtures/gameArchiveFixture.js";
import {
  binaryResource,
  compressedFile,
  FASTLZ_MATCH,
  gdec3,
  gdec4,
  godot3Script,
  godot4Script,
  mv,
  passwordKey,
  projectBinary,
  rv,
  sceneBundle,
  storeVar,
  token3,
  u32,
} from "../../../fixtures/godotFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const service = createGodotFileService({
  GODOT_KEY: KEY,
  GODOT_PASSWORD: "hunter2",
  WRONG_KEY: "ff".repeat(32),
  SHORT_KEY: "abcd",
});
let root = "";
const path = (name: string) => join(root, name);

const resource4 = () =>
  binaryResource({
    major: 4,
    minor: 5,
    format: 6,
    type: "Resource",
    flags: 1 | 2 | 8,
    uid: 123456789n,
    scriptClass: "PlayerData",
    strings: [
      "count",
      "ratio",
      "name",
      "action",
      "offset",
      "tint",
      "target",
      "table",
      "scores",
      "tags",
      "raw",
      "icon",
      "gradient",
      "cell",
      "xform",
      "offsets",
      "Sprite",
      "position",
    ],
    external: [{ type: "Texture2D", path: "res://icon.png", uid: 42n }],
    internal: [
      {
        path: "local://Gradient_x1",
        type: "Gradient",
        properties: [[15, rv.float32s([0, 0.5, 1])]],
      },
      {
        path: "res://data.res",
        type: "Resource",
        properties: [
          [0, rv.int(42)],
          [1, rv.float(0.1)],
          [2, rv.string('Ana "the"\nbrave')],
          [3, rv.stringName("run")],
          [4, rv.vector2(1.5, -2)],
          [5, rv.color(1, 0.5, 0, 1)],
          [6, rv.nodePath([16], [17])],
          [
            7,
            rv.dictionary([
              [rv.string("a"), rv.array([rv.int(1), rv.string("b"), rv.nil()])],
            ]),
          ],
          [8, rv.int32s([1, -2])],
          [9, rv.strings(["x", "ü"])],
          [10, rv.bytes([1, 2, 3])],
          [11, rv.external(0)],
          [12, rv.internal(0)],
          [13, rv.vector3i(1, -2, 3)],
          [14, rv.transform2d(1, 0, 0, 1, 5, 6)],
        ],
      },
    ],
  });

const scene4 = () =>
  binaryResource({
    major: 4,
    minor: 5,
    format: 6,
    type: "PackedScene",
    flags: 1 | 2,
    strings: ["_bundled"],
    external: [{ type: "PackedScene", path: "res://enemy.tscn" }],
    internal: [
      {
        path: "local://PackedScene_main",
        type: "PackedScene",
        properties: [
          [
            0,
            sceneBundle({
              names: [
                "Level",
                "Node2D",
                "Player",
                "Sprite2D",
                "position",
                "players",
                "persist",
                "Timer",
                "timeout",
                "hide",
                "Enemy",
                "visibility_changed",
                "start",
              ],
              variants: [
                rv.vector2(10, 20),
                rv.external(0),
                rv.float(2.5),
                rv.string("fast"),
              ],
              nodes: [
                { parent: -1, type: 1, name: 0 },
                {
                  parent: 0,
                  type: 3,
                  name: 2,
                  properties: [[4, 0]],
                  groups: [5, 6],
                },
                { parent: 0, type: 7, name: 7 },
                { parent: 1, type: 0x7fffffff, name: 10, instance: 1 },
              ],
              connections: [
                [2, 1, 8, 9, 2, 0, 0],
                [1, 2, 11, 12, 3, 2, 2, 3, 1],
              ],
            }),
          ],
        ],
      },
    ],
  });

/** extends Node2D / func _ready(): / var v = Vector2(1, 2) / print($Sprite/Child, -v) */
const script3 = () =>
  godot3Script({
    identifiers: ["Node2D", "_ready", "v", "Sprite", "Child"],
    constants: [mv.int(1), mv.int(2)],
    lines: [
      [0, 1],
      [3, 2],
      [4, 3],
      [10, 4],
      [20, 5],
      [31, 6],
    ],
    tokens: [
      51,
      token3(1, 0),
      89,
      89,
      48,
      token3(1, 1),
      80,
      81,
      86,
      token3(89, 1),
      59,
      token3(1, 2),
      23,
      token3(4, 5),
      80,
      token3(2, 0),
      82,
      token3(2, 1),
      81,
      token3(89, 1),
      token3(5, 63),
      80,
      87,
      token3(1, 3),
      19,
      token3(1, 4),
      82,
      17,
      token3(1, 2),
      81,
      89,
      96,
    ],
  });

/** @tool / extends Node / func hit(amount := -1) -> void: / if amount != 0: / emit_signal(&"hit", ^"Path:x") / return */
const script4 = (compress: boolean) =>
  godot4Script({
    version: 101,
    compress,
    identifiers: ["@tool", "Node", "hit", "amount", "emit_signal"],
    constants: [
      mv.int(-1),
      mv.int(0),
      mv.stringName("hit"),
      mv.nodePath4(["Path"], ["x"]),
    ],
    starts: [
      [1, 2, 1],
      [3, 4, 1],
      [14, 5, 5],
      [19, 6, 9],
      [25, 7, 5],
    ],
    tokens: [
      [1, 1, 0],
      [59, 2],
      [2, 2, 1],
      [60, 4],
      [2, 4, 2],
      [77, 4],
      [2, 4, 3],
      [84, 4],
      [28, 4],
      [3, 4, 0],
      [78, 4],
      [86, 4],
      [71, 4],
      [84, 4],
      [40, 5],
      [2, 5, 3],
      [9, 5],
      [3, 5, 1],
      [84, 5],
      [2, 6, 4],
      [77, 6],
      [3, 6, 2],
      [79, 6],
      [3, 6, 3],
      [78, 6],
      [48, 7],
    ],
  });

const save4 = () =>
  storeVar([
    mv.dictionary([
      [mv.string("player"), mv.string("Ana")],
      [mv.string("hp"), mv.int(87)],
      [mv.string("pos"), mv.vector2(1.5, -2)],
      [mv.string("items"), mv.typedArray(2, [mv.int(1), mv.int(2)])],
      [mv.int(7), mv.stringName("seven")],
      [mv.string("path"), mv.nodePath4(["World", "Player"], ["position"])],
      [
        mv.string("obj"),
        mv.object("Resource", [["resource_name", mv.string("x")]]),
      ],
      [mv.string("big"), mv.int64(12345678901n)],
    ]),
    mv.string("second"),
  ]);

const save3 = () =>
  storeVar([
    mv.dictionary(
      [
        [mv.string("gold"), mv.int(5)],
        [mv.string("scores"), mv.packedInt32([3, 4], 3)],
      ],
      3,
    ),
  ]);

const files = (): Record<string, Buffer> => {
  const remap = (target: string) =>
    Buffer.from(`[remap]\n\npath="res://${target}"\n`);
  const pack = createGodotPack({
    version: 3,
    engine: [4, 5, 1],
    files: [
      { path: "player.gd.remap", data: remap("player.gdc") },
      { path: "player.gdc", data: script4(true) },
      {
        path: "level.tscn.remap",
        data: remap(".godot/exported/133200997/export-level.scn"),
      },
      { path: ".godot/exported/133200997/export-level.scn", data: scene4() },
      {
        path: "project.binary",
        data: projectBinary([["application/config/name", mv.string("Demo")]]),
      },
      { path: "secret.gdc", data: script4(false) },
    ],
    encryptedPaths: ["secret.gdc"],
  });
  return {
    "data.res": resource4(),
    "level.scn": scene4(),
    "anim.res": binaryResource({
      major: 3,
      minor: 5,
      format: 3,
      type: "Animation",
      flags: 0,
      strings: ["length", "loop", "tracks/0/keys"],
      external: [],
      internal: [
        {
          path: "local://1",
          type: "Animation",
          properties: [
            [0, rv.float(2.5)],
            [1, rv.bool(true)],
            [2, rv.dictionary([[rv.string("times"), rv.float32s([0, 1])]])],
          ],
        },
      ],
      compress: true,
    }),
    "player3.gdc": script3(),
    "player4.gdc": script4(false),
    "player4z.gdc": script4(true),
    "speed.gdc": godot4Script({
      version: 100,
      identifiers: ["speed"],
      constants: [mv.float(2.5)],
      starts: [],
      tokens: [
        [70, 1],
        [2, 1, 0],
        [28, 1],
        [3, 1, 0],
      ],
    }),
    "save4.dat": save4(),
    "save3.dat": save3(),
    "one.bin": mv.string("just one"),
    "project.binary": projectBinary([
      ["application/config/name", mv.string("Demo")],
      [
        "input/jump",
        mv.dictionary([
          [mv.string("deadzone"), mv.float(0.5)],
          [
            mv.string("events"),
            mv.array([mv.object("InputEventKey", [["keycode", mv.int(32)]])]),
          ],
        ]),
      ],
    ]),
    "save_fastlz.dat": compressedFile("GCPF", save4(), 0),
    "save_deflate.dat": compressedFile("GCPF", save4(), 1, 64),
    "save_gzip.dat": compressedFile("GCPF", save4(), 3),
    "match.dat": Buffer.concat([
      Buffer.from("GCPF"),
      u32(0),
      u32(4096),
      u32(20),
      u32(FASTLZ_MATCH.length),
      FASTLZ_MATCH,
    ]),
    "save_key.dat": gdec4(save4(), Buffer.from(KEY, "hex")),
    "save_password.dat": gdec3(save4(), passwordKey("hunter2")),
    "game.pck": pack,
    "game.exe": embedInExecutable(
      pack,
      Buffer.from("MZ fake executable\0\0\0\0"),
    ),
    "junk.bin": Buffer.from("\x01\x02\x03 not a godot file", "latin1"),
    "future.gdc": Buffer.concat([
      Buffer.from("GDSC"),
      u32(102),
      Buffer.alloc(16),
    ]),
  };
};

beforeAll(async () => {
  root = (await createTestWorkspace("rea-godot-")).root;
  for (const [name, bytes] of Object.entries(files()))
    await writeFile(path(name), bytes);
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as GodotFileReport;
};
const values = (report: GodotFileReport) =>
  Object.fromEntries(report.values.map(({ path: at, value }) => [at, value]));

describe("binary resources and scenes", () => {
  it("reads a Godot 4 resource's header, references and every value type", async () => {
    const report = await inspect({
      path: path("data.res"),
      view: "properties",
      resource: "main",
    });
    expect(report.kind).toBe("resource");
    expect(report.resource).toMatchObject({
      engine: "4.5",
      format: 6,
      type: "Resource",
      uid: "uid://cyncsb",
      script_class: "PlayerData",
      flags: ["named_scene_ids", "uids", "has_script_class"],
      external: 1,
      internal: 2,
      trailer: true,
    });
    expect(
      report.properties.map(({ name, type, value }) => [name, type, value]),
    ).toEqual([
      ["count", "int", "42"],
      ["ratio", "float", "0.1"],
      ["name", "String", '"Ana \\"the\\"\\nbrave"'],
      ["action", "StringName", '&"run"'],
      ["offset", "Vector2", "Vector2(1.5, -2)"],
      ["tint", "Color", "Color(1, 0.5, 0, 1)"],
      ["target", "NodePath", 'NodePath("Sprite:position")'],
      ["table", "Dictionary", '{"a": [1, "b", null]}'],
      ["scores", "PackedInt32Array", "PackedInt32Array(1, -2)"],
      ["tags", "PackedStringArray", 'PackedStringArray("x", "ü")'],
      ["raw", "PackedByteArray", "PackedByteArray(1, 2, 3)"],
      ["icon", "Resource", 'ExtResource("res://icon.png")'],
      ["gradient", "Resource", 'SubResource("Gradient_x1")'],
      ["cell", "Vector3i", "Vector3i(1, -2, 3)"],
      ["xform", "Transform2D", "Transform2D(1, 0, 0, 1, 5, 6)"],
    ]);
    const resources = await inspect({ path: path("data.res") });
    expect(
      resources.resources.map(({ id, kind, type, path: at, uid }) => [
        id,
        kind,
        type,
        at,
        uid,
      ]),
    ).toEqual([
      ["ext:1", "external", "Texture2D", "res://icon.png", "uid://bi"],
      ["Gradient_x1", "internal", "Gradient", null, null],
      ["main", "main", "Resource", null, "uid://cyncsb"],
    ]);
  });

  it("reads a scene's nodes, instanced scenes, groups and connections", async () => {
    const nodes = await inspect({ path: path("level.scn") });
    expect(nodes.kind).toBe("scene");
    expect(
      nodes.nodes.map(
        ({ path: at, parent, type, instance, groups, properties }) => [
          at,
          parent,
          type,
          instance,
          groups,
          properties,
        ],
      ),
    ).toEqual([
      [".", null, "Node2D", null, [], 0],
      ["Player", ".", "Sprite2D", null, ["players", "persist"], 1],
      ["Timer", ".", "Timer", null, [], 0],
      [
        "Player/Enemy",
        "Player",
        null,
        'ExtResource("res://enemy.tscn")',
        [],
        0,
      ],
    ]);
    const connections = await inspect({
      path: path("level.scn"),
      view: "connections",
    });
    expect(connections.connections).toEqual([
      {
        from: "Timer",
        signal: "timeout",
        to: "Player",
        method: "hide",
        flags: ["persist"],
        binds: [],
        unbinds: 0,
      },
      {
        from: "Player",
        signal: "visibility_changed",
        to: "Timer",
        method: "start",
        flags: ["deferred", "persist"],
        binds: ["2.5", '"fast"'],
        unbinds: 1,
      },
    ]);
    const player = await inspect({
      path: path("level.scn"),
      view: "properties",
      node: "Player",
    });
    expect(player.properties).toEqual([
      {
        owner_kind: "node",
        owner: "Player",
        name: "position",
        type: "Vector2",
        value: "Vector2(10, 20)",
        truncated: false,
      },
    ]);
    const subtree = await inspect({ path: path("level.scn"), node: "Player" });
    expect(subtree.nodes.map(({ path: at }) => at)).toEqual([
      "Player",
      "Player/Enemy",
    ]);
  });

  it("reads Godot 3 resources compressed with RSCC, in Godot 3's type names", async () => {
    const report = await inspect({
      path: path("anim.res"),
      view: "properties",
    });
    expect(report.resource).toMatchObject({
      engine: "3.5",
      format: 3,
      type: "Animation",
      flags: ["compressed_zstd"],
      trailer: true,
    });
    expect(
      report.properties.map(({ owner, name, value }) => [owner, name, value]),
    ).toEqual([
      ["main", "length", "2.5"],
      ["main", "loop", "true"],
      ["main", "tracks/0/keys", '{"times": PoolRealArray(0, 1)}'],
    ]);
  });
});

describe("compiled GDScript", () => {
  it("rebuilds Godot 3 bytecode with built-ins, node paths and indentation", async () => {
    const report = await inspect({ path: path("player3.gdc") });
    expect(report.script).toEqual({
      version: 13,
      engine: "3.1-3.6",
      compressed: false,
      identifiers: 5,
      constants: 2,
      tokens: 32,
    });
    expect(report.source).toEqual([
      { line: 1, text: "extends Node2D" },
      { line: 3, text: "func _ready():" },
      { line: 4, text: "\tvar v = Vector2(1, 2)" },
      { line: 5, text: "\tprint($Sprite/Child, -v)" },
    ]);
    const tokens = await inspect({
      path: path("player3.gdc"),
      view: "tokens",
      query: "BUILT_IN",
    });
    expect(
      tokens.tokens.map(({ type, text, line }) => [type, text, line]),
    ).toEqual([
      ["BUILT_IN_TYPE", "Vector2", 4],
      ["BUILT_IN_FUNC", "print", 5],
    ]);
  });

  it("rebuilds Godot 4 tokens, plain and zstd-compressed, from logical-line columns", async () => {
    const expected = [
      { line: 1, text: "@tool" },
      { line: 2, text: "extends Node" },
      { line: 4, text: "func hit(amount := -1) -> void:" },
      { line: 5, text: "\tif amount != 0:" },
      { line: 6, text: '\t\temit_signal(&"hit", ^"Path:x")' },
      { line: 7, text: "\treturn" },
    ];
    for (const name of ["player4.gdc", "player4z.gdc"]) {
      const report = await inspect({ path: path(name) });
      expect(report.script, name).toMatchObject({
        version: 101,
        engine: "4.5+",
        compressed: name === "player4z.gdc",
        tokens: 26,
      });
      expect(report.source, name).toEqual(expected);
    }
    const older = await inspect({ path: path("speed.gdc") });
    expect([older.script?.engine, older.source]).toEqual([
      "4.3-4.4",
      [{ line: 1, text: "var speed = 2.5" }],
    ]);
  });
});

describe("saves, settings and containers", () => {
  it("reads store_var values with paths, typed arrays and inline objects", async () => {
    const report = await inspect({ path: path("save4.dat"), limit: 50 });
    expect(report.variant).toEqual({
      engine: "4",
      values: 2,
      encoding: "store_var",
      also_reads_as: null,
    });
    expect(values(report)).toMatchObject({
      "$[0].player": '"Ana"',
      "$[0].hp": "87",
      "$[0].pos": "Vector2(1.5, -2)",
      "$[0].items": "Array[int]([1, 2])",
      "$[0].items[1]": "2",
      "$[0][7]": '&"seven"',
      "$[0].path": 'NodePath("World/Player:position")',
      "$[0].obj.resource_name": '"x"',
      "$[0].big": "12345678901",
      "$[1]": '"second"',
    });
    expect(
      report.values.find(({ path: at }) => at === "$[0].obj"),
    ).toMatchObject({ type: "Resource", children: 1 });
    const godot3 = await inspect({ path: path("save3.dat") });
    expect([godot3.variant?.engine, values(godot3)["$.scores"]]).toEqual([
      "3",
      "PoolIntArray(3, 4)",
    ]);
    const one = await inspect({ path: path("one.bin") });
    expect([one.variant?.encoding, values(one)["$"]]).toEqual([
      "var_to_bytes",
      '"just one"',
    ]);
  });

  it("reads project.binary settings, including inline input events", async () => {
    const report = await inspect({
      path: path("project.binary"),
      query: "keycode",
    });
    expect(report.variant?.encoding).toBe("project_settings");
    // Containers print their contents too, so they match the query as well.
    expect(report.values.map(({ path: at }) => at)).toEqual([
      "$",
      '$["input/jump"]',
      '$["input/jump"].events',
      '$["input/jump"].events[0]',
      '$["input/jump"].events[0].keycode',
    ]);
    expect(values(report)['$["input/jump"].events[0].keycode']).toBe("32");
  });

  it("removes open_compressed and open_encrypted layers", async () => {
    for (const [name, format] of [
      ["save_fastlz.dat", "GCPF fastlz"],
      ["save_deflate.dat", "GCPF deflate"],
      ["save_gzip.dat", "GCPF gzip"],
    ] as const) {
      const report = await inspect({ path: path(name), limit: 1 });
      expect(
        [report.layers.map((layer) => layer.format), report.variant?.values],
        name,
      ).toEqual([[format], 2]);
    }
    const match = await inspect({ path: path("match.dat") });
    expect(values(match)["$"]).toBe('"abcabcabcabc"');
    const keyed = await inspect({
      path: path("save_key.dat"),
      key_env: "GODOT_KEY",
      limit: 1,
    });
    expect(keyed.layers).toMatchObject([
      {
        kind: "decrypted",
        format: "GDEC (Godot 4)",
        output_bytes: save4().length,
      },
    ]);
    const password = await inspect({
      path: path("save_password.dat"),
      password_env: "GODOT_PASSWORD",
      limit: 1,
    });
    expect(password.layers).toMatchObject([{ format: "GDEC (Godot 3)" }]);
  });
});

describe("packs and refusals", () => {
  it("reads pack entries through .remap, also inside an executable", async () => {
    for (const name of ["game.pck", "game.exe"]) {
      const script = await inspect({
        path: path(name),
        entry: "res://player.gd",
      });
      expect(script.entry, name).toMatchObject({
        path: "player.gdc",
        remapped_from: "player.gd",
        pack_engine: "4.5.1",
      });
      expect(script.source[0], name).toEqual({ line: 1, text: "@tool" });
    }
    const scene = await inspect({
      path: path("game.pck"),
      entry: "level.tscn",
      view: "connections",
    });
    expect(scene.connections).toHaveLength(2);
    const settings = await inspect({
      path: path("game.pck"),
      entry: "project.binary",
    });
    expect(values(settings)['$["application/config/name"]']).toBe('"Demo"');
  });

  it("refuses selections that do not fit, and keys that do not decrypt", async () => {
    for (const [input, field] of [
      [{ path: path("data.res"), view: "nodes" }, "view"],
      [{ path: path("player4.gdc"), view: "values" }, "view"],
      [{ path: path("data.res"), resource: "nope" }, "resource"],
      [{ path: path("level.scn"), node: "Nobody" }, "node"],
      [{ path: path("player4.gdc"), node: "." }, "node"],
      [{ path: path("game.pck"), entry: "missing.gd" }, "entry"],
      [{ path: path("game.pck"), entry: "secret.gdc" }, "entry"],
      [{ path: path("data.res"), entry: "x" }, "entry"],
      [{ path: path("save_key.dat") }, "key_env"],
      [{ path: path("save_key.dat"), key_env: "WRONG_KEY" }, "key_env"],
      [{ path: path("save_key.dat"), key_env: "SHORT_KEY" }, "key_env"],
      [{ path: path("save_key.dat"), key_env: "NOT_SET" }, "key_env"],
      [
        { path: path("save_password.dat"), password_env: "GODOT_KEY" },
        "password_env",
      ],
      [{ path: path("junk.bin") }, "path"],
      [{ path: path("future.gdc") }, "path"],
    ] as const)
      expect(await service.inspect(input), JSON.stringify(input)).toMatchObject(
        { ok: false, error: { issues: [{ path: [field] }] } },
      );
    expect(
      await service.inspect({
        path: path("save_key.dat"),
        key_env: "lower case",
      }),
    ).toMatchObject({ ok: false });
  });
});
