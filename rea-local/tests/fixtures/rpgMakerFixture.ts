import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { crc32, deflateSync } from "node:zlib";

/**
 * RPG Maker MV/MZ games built in source: the JSON database and maps the editor
 * writes, plugins.js, assets encrypted the way the deploy step encrypts them,
 * and saves in each generation's format (MV: LZString base64, MZ: zlib).
 */

export const FIXTURE_KEY = "0123456789abcdef0123456789abcdef";
export const FIXTURE_TIMESTAMP = Date.UTC(2026, 0, 1);

const RPGMV_HEADER = Buffer.from("5250474d560000000003010000000000", "hex");

const chunk = (type: string, data: Buffer): Buffer => {
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
};

/** A valid RGBA PNG of the given size. */
export const createPng = (width: number, height: number): Buffer => {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, 6, 0, 0, 0], 8);
  const rows = Buffer.alloc(height * (1 + width * 4), 0x7f);
  for (let row = 0; row < height; row += 1) rows[row * (1 + width * 4)] = 0;
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(rows)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
};

/** The deploy step's encryption: RPGMV header, first 16 bytes XORed with the key. */
export const encryptAsset = (plain: Buffer, key = FIXTURE_KEY): Buffer => {
  const body = Buffer.from(plain);
  const keyBytes = Buffer.from(key, "hex");
  for (let index = 0; index < 16 && index < body.length; index += 1)
    body[index] = (body[index] ?? 0) ^ (keyBytes[index] ?? 0);
  return Buffer.concat([RPGMV_HEADER, body]);
};

/**
 * LZString.compressToBase64 as RPG Maker MV bundles it (lz-string 1.3): the
 * LZ bit stream packed into 16-bit characters, then base64 of those
 * characters' big-endian bytes.
 */
export const lzCompressToBase64 = (input: string): string => {
  const dictionary = new Map<string, number>();
  const toCreate = new Set<string>();
  const out: number[] = [];
  let value = 0;
  let position = 0;
  let enlarge = 2;
  let size = 3;
  let bits = 2;
  let w = "";
  const write = (number: number, count: number) => {
    let rest = number;
    for (let index = 0; index < count; index += 1) {
      value = ((value << 1) | (rest & 1)) & 0xffff;
      if (position === 15) {
        position = 0;
        out.push(value);
        value = 0;
      } else position += 1;
      rest >>= 1;
    }
  };
  const grow = () => {
    enlarge -= 1;
    if (enlarge === 0) {
      enlarge = 2 ** bits;
      bits += 1;
    }
  };
  const emit = (word: string) => {
    if (toCreate.has(word)) {
      const code = word.charCodeAt(0);
      if (code < 256) {
        write(0, bits);
        write(code, 8);
      } else {
        write(1, bits);
        write(code, 16);
      }
      grow();
      toCreate.delete(word);
    } else write(dictionary.get(word) ?? 0, bits);
    grow();
  };
  for (let index = 0; index < input.length; index += 1) {
    const c = input.charAt(index);
    if (!dictionary.has(c)) {
      dictionary.set(c, size);
      size += 1;
      toCreate.add(c);
    }
    if (dictionary.has(w + c)) w += c;
    else {
      emit(w);
      dictionary.set(w + c, size);
      size += 1;
      w = c;
    }
  }
  if (w !== "") emit(w);
  write(2, bits);
  for (;;) {
    value = (value << 1) & 0xffff;
    if (position === 15) {
      out.push(value);
      break;
    }
    position += 1;
  }
  const bytes = Buffer.alloc(out.length * 2);
  out.forEach((char, index) => bytes.writeUInt16BE(char, index * 2));
  return bytes.toString("base64");
};

/** MZ: pako.deflate(json, {to: "string"}), which NW.js writes out as UTF-8. */
export const mzSaveBytes = (json: string): Buffer =>
  Buffer.from(
    deflateSync(Buffer.from(json, "utf8"), { level: 1 }).toString("latin1"),
    "utf8",
  );

type Command = readonly [number, ...unknown[]];
const list = (...commands: Command[]) =>
  [...commands, [0]].map(([code, ...parameters]) => ({
    code,
    indent: 0,
    parameters,
  }));

const page = (conditions: object, ...commands: Command[]) => ({
  conditions,
  list: list(...commands),
  trigger: 0,
});

const village = (engine: "mv" | "mz") => ({
  displayName: "Green Village",
  width: 20,
  height: 15,
  tilesetId: 1,
  bgm: { name: "Town1", pan: 0, pitch: 100, volume: 90 },
  events: [
    null,
    {
      id: 1,
      name: "Elder",
      x: 5,
      y: 6,
      pages: [
        page(
          {},
          [101, "Actor1", 2, 0, 2, ...(engine === "mz" ? ["Elder"] : [])],
          [401, "Welcome, \\N[1]!"],
          [401, "The cave is \\C[2]north\\C[0]."],
          [102, ["Go to the cave", "Stay"], 1, 0, 2, 0],
          [402, 0, "Go to the cave"],
          [121, 1, 1, 0],
          [201, 0, 2, 10, 12, 2, 0],
          [402, 1, "Stay"],
          [122, 1, 1, 1, 1, 2],
          [404],
          [117, 1],
        ),
        page(
          {
            switch1Valid: true,
            switch1Id: 1,
            variableValid: true,
            variableId: 2,
            variableValue: 5,
          },
          [105, 2, false],
          [405, "Credits line 1"],
          [405, "Credits line 2"],
          [108, "<quest:start>"],
          [408, "second comment line"],
        ),
      ],
    },
    {
      id: 2,
      name: "Sign",
      x: 8,
      y: 2,
      pages: [
        page(
          {},
          [111, 0, 3, 0],
          [101, "", 0, 0, 2],
          [401, "The boss is gone."],
          [412],
        ),
      ],
    },
  ],
});

const DATABASE = (engine: "mv" | "mz") => ({
  "System.json": {
    gameTitle: "Fixture Quest",
    locale: "en_US",
    versionId: 123456,
    startMapId: 1,
    startX: 3,
    startY: 4,
    switches: ["", "door_open", "", "boss_beaten", "timer_on"],
    variables: ["", "gold_found", "steps_left"],
    hasEncryptedImages: true,
    hasEncryptedAudio: true,
    encryptionKey: FIXTURE_KEY,
    ...(engine === "mz"
      ? { advanced: { gameId: 4242, screenWidth: 816 } }
      : {}),
  },
  "MapInfos.json": [
    null,
    { id: 1, name: "Village", order: 1, parentId: 0 },
    { id: 2, name: "Cave", order: 2, parentId: 1 },
    { id: 3, name: "Unused", order: 3, parentId: 0 },
  ],
  "Map001.json": village(engine),
  "Map002.json": {
    displayName: "",
    width: 10,
    height: 10,
    tilesetId: 2,
    bgm: { name: "" },
    events: [
      null,
      { id: 1, name: "Exit", pages: [page({}, [201, 1, 3, 4, 5, 0, 0])] },
    ],
  },
  "CommonEvents.json": [
    null,
    {
      id: 1,
      name: "Heal",
      trigger: 0,
      switchId: 1,
      list: list([101, "", 0, 0, 2, ""], [401, "You feel rested."]),
    },
    { id: 2, name: "Timer", trigger: 2, switchId: 4, list: list() },
  ],
  "Troops.json": [
    null,
    {
      id: 1,
      name: "Slime*2",
      members: [],
      pages: [
        {
          conditions: { switchValid: true, switchId: 3 },
          list: list([101, "", 0, 0, 2, ""], [401, "The slimes wobble."]),
          span: 0,
        },
      ],
    },
  ],
  "Actors.json": [
    null,
    {
      id: 1,
      name: "Hero",
      nickname: "",
      classId: 1,
      initialLevel: 1,
      faceName: "Actor1",
      faceIndex: 0,
      note: "<Biography:A hero>\n<HP Regen>",
      profile: "",
    },
  ],
  "Items.json": [
    null,
    {
      id: 1,
      name: "Potion",
      description: "Restores 100 HP",
      price: 50,
      iconIndex: 176,
      note: "",
    },
    {
      id: 2,
      name: "Cave Key",
      description: "Opens the cave",
      price: 0,
      iconIndex: 195,
      note: "<Key Item>",
    },
  ],
  "Weapons.json": [
    null,
    { id: 1, name: "Sword", description: "", price: 500, note: "" },
  ],
  "Armors.json": [
    null,
    { id: 1, name: "Shield", description: "", price: 300, note: "" },
  ],
  "Classes.json": [null, { id: 1, name: "Warrior", note: "" }],
  "Skills.json": [null],
  "Enemies.json": [null, { id: 1, name: "Slime", exp: 3, gold: 2, note: "" }],
  "States.json": [null],
  "Animations.json": [null],
  "Tilesets.json": [
    null,
    { id: 1, name: "Field", tilesetNames: ["World_A1"], note: "" },
  ],
});

const PLUGINS = `// Generated by RPG Maker.
// Do not edit this file directly.
var $plugins =
[
{"name":"FixturePlugin","status":true,"description":"Adds things","parameters":{"Speed":"4","List":"[\\"a\\"]"}},
{"name":"MissingPlugin","status":false,"description":"Not shipped","parameters":{}}
];
`;

/** A JsonEx-encoded save: "@c" ids, "@" class names, arrays wrapped in "@a". */
export const FIXTURE_SAVE = JSON.stringify({
  system: {
    "@": "Game_System",
    "@c": 2,
    _versionId: 123456,
    _framesOnSave: 3661 * 60 + 30,
  },
  switches: {
    "@": "Game_Switches",
    "@c": 3,
    _data: { "@c": 4, "@a": [null, true, false, true] },
  },
  variables: {
    "@": "Game_Variables",
    "@c": 5,
    _data: { "@c": 6, "@a": [null, 7, 0, "north"] },
  },
  selfSwitches: {
    "@": "Game_SelfSwitches",
    "@c": 7,
    _data: { "@c": 8, "1,1,A": true, "1,2,A": false },
  },
  actors: {
    "@": "Game_Actors",
    "@c": 9,
    _data: {
      "@c": 10,
      "@a": [
        null,
        {
          "@": "Game_Actor",
          "@c": 11,
          _actorId: 1,
          _name: "Hero",
          _level: 5,
          _hp: 120,
          _mp: 30,
          _party: { "@r": 12 },
        },
      ],
    },
  },
  party: {
    "@": "Game_Party",
    "@c": 12,
    _gold: 999,
    _steps: 42,
    _actors: { "@c": 13, "@a": [1] },
    _items: { "@c": 14, "1": 3, "2": 1 },
    _weapons: { "@c": 15, "1": 1 },
    _armors: { "@c": 16 },
  },
  map: { "@": "Game_Map", "@c": 17, _mapId: 2 },
  player: { "@": "Game_Player", "@c": 18, _x: 10, _y: 12 },
  "@c": 1,
});

const GLOBAL = JSON.stringify([
  null,
  {
    globalId: "RPGMV",
    title: "Fixture Quest",
    characters: [],
    faces: [],
    playtime: "01:01:01",
    timestamp: FIXTURE_TIMESTAMP,
  },
]);

const put = async (path: string, data: string | Buffer) => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, data);
};

/** Write a deployed game: MV under www/ with .rpgmv* assets, MZ at the top with *_ assets. */
export const createRpgMakerGame = async (
  root: string,
  engine: "mv" | "mz",
): Promise<string> => {
  const base = engine === "mv" ? join(root, "www") : root;
  const image = engine === "mv" ? ".rpgmvp" : ".png_";
  const audio = engine === "mv" ? ".rpgmvo" : ".ogg_";
  const save = engine === "mv" ? ".rpgsave" : ".rmmzsave";
  const encode = (json: string) =>
    engine === "mv" ? lzCompressToBase64(json) : mzSaveBytes(json);
  for (const [name, value] of Object.entries(DATABASE(engine)))
    await put(join(base, "data", name), JSON.stringify(value));
  await put(
    join(base, "js", engine === "mv" ? "rpg_core.js" : "rmmz_core.js"),
    `//=====\n// ${engine === "mv" ? "rpg_core.js v1.6.2" : "rmmz_core.js v1.8.0"}\n//=====\n`,
  );
  await put(join(base, "js", "plugins.js"), PLUGINS);
  await put(
    join(base, "js", "plugins", "FixturePlugin.js"),
    "// FixturePlugin\n",
  );
  await put(
    join(base, "img", "faces", `Actor1${image}`),
    encryptAsset(createPng(4, 2)),
  );
  await put(join(base, "img", "system", "Window.png"), createPng(2, 2));
  await put(
    join(base, "img", "pictures", `broken${image}`),
    Buffer.from("not encrypted at all"),
  );
  await put(
    join(base, "audio", "se", `Cursor1${audio}`),
    encryptAsset(Buffer.concat([Buffer.from("OggS"), Buffer.alloc(60, 1)])),
  );
  await put(join(base, "save", `file1${save}`), encode(FIXTURE_SAVE));
  await put(join(base, "save", `global${save}`), encode(GLOBAL));
  await put(
    join(base, "save", `config${save}`),
    encode(JSON.stringify({ alwaysDash: true })),
  );
  await put(join(base, "save", "notes.txt"), "not a save");
  return root;
};
