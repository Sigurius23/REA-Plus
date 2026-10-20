import { inflateSync } from "node:zlib";

import type { RpgMakerProjectReport } from "../domain/rpgmaker/rpgMakerProject.js";
import { decompressFromBase64 } from "./LzString.js";
import { RpgMakerFormatError, type ReadFile } from "./RpgMakerFiles.js";
import {
  arrayOf,
  idOf,
  intOf,
  numberOf,
  recordOf,
  stringOf,
  type JsonRecord,
} from "./RpgMakerJson.js";

type Save = RpgMakerProjectReport["saves"][number];
const MAX_SAVE_TEXT = 64 * 1024 * 1024;

/** Save files the engine writes: file<N>, global and config, in either generation. */
export const SAVE_NAME = /^(file(\d+)|global|config)\.(rpgsave|rmmzsave)$/u;

/**
 * Undo JsonEx: arrays inside objects are wrapped as {"@a": [...]}, and "@c"
 * ids, "@" class names and "@r" back-references are metadata. References
 * become null; class names are only recorded, never resolved.
 */
const unwrap = (value: unknown, depth = 0): unknown => {
  if (depth > 100) return null;
  if (Array.isArray(value)) return value.map((item) => unwrap(item, depth + 1));
  const record = recordOf(value);
  if (record === null) return value;
  if ("@a" in record) return unwrap(record["@a"], depth + 1);
  if ("@r" in record) return null;
  return Object.fromEntries(
    Object.entries(record)
      .filter(([key]) => key !== "@c" && key !== "@")
      .map(([key, item]) => [key, unwrap(item, depth + 1)]),
  );
};

/** MZ: pako's binary string written as UTF-8 by NW.js, then zlib. */
const inflateMz = (text: string): string => {
  const bytes = Buffer.alloc(text.length);
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code > 0xff)
      throw new RpgMakerFormatError("Save is not a zlib binary string");
    bytes[index] = code;
  }
  return inflateSync(bytes, { maxOutputLength: MAX_SAVE_TEXT }).toString(
    "utf8",
  );
};

/** Decode one save file into plain JSON data. */
export const decodeSave = (file: ReadFile, format: Save["format"]): unknown => {
  const text = file.bytes.toString("utf8");
  let json: string;
  try {
    json =
      format === "lz-string"
        ? decompressFromBase64(text, MAX_SAVE_TEXT)
        : inflateMz(text);
    return unwrap(JSON.parse(json));
  } catch (cause) {
    throw new RpgMakerFormatError(
      `${file.path} is not a readable ${format === "lz-string" ? "MV" : "MZ"} save`,
      { cause },
    );
  }
};

export interface SaveNames {
  readonly switches: readonly unknown[];
  readonly variables: readonly unknown[];
  readonly maps: ReadonlyMap<number, string | null>;
  readonly actors: ReadonlyMap<number, string>;
  readonly items: Readonly<
    Record<"item" | "weapon" | "armor", ReadonlyMap<number, string>>
  >;
}

const nameAt = (names: readonly unknown[], id: number): string | null => {
  const name = stringOf(names[id]);
  return name === null || name.length === 0 ? null : name;
};

const scalarOf = (value: unknown): string | number | boolean | null => {
  if (value === null || ["string", "number", "boolean"].includes(typeof value))
    return value as string | number | boolean | null;
  const text = JSON.stringify(value);
  return text.length > 200 ? `${text.slice(0, 200)}…` : text;
};

const dataOf = (owner: unknown): unknown => recordOf(owner)?.["_data"];

const partyOf = (save: JsonRecord, names: SaveNames): Save["party"] => {
  const actors = arrayOf(dataOf(save["actors"]));
  return arrayOf(recordOf(save["party"])?.["_actors"]).flatMap((value) => {
    const id = idOf(value);
    if (id === null) return [];
    const actor = recordOf(actors[id]);
    return [
      {
        actor_id: id,
        name: stringOf(actor?.["_name"]) ?? names.actors.get(id) ?? null,
        level: intOf(actor?.["_level"]),
        hp: numberOf(actor?.["_hp"]),
        mp: numberOf(actor?.["_mp"]),
      },
    ];
  });
};

const itemsOf = (party: JsonRecord | null, names: SaveNames): Save["items"] =>
  (
    [
      ["item", "_items"],
      ["weapon", "_weapons"],
      ["armor", "_armors"],
    ] as const
  ).flatMap(([kind, key]) =>
    Object.entries(recordOf(party?.[key]) ?? {}).flatMap(([id, amount]) => {
      const number = Number(id);
      const value = numberOf(amount);
      return Number.isInteger(number) && value !== null
        ? [
            {
              kind,
              id: number,
              name: names.items[kind].get(number) ?? null,
              count: value,
            },
          ]
        : [];
    }),
  );

const savedAt = (
  global: readonly unknown[] | null,
  slot: number | null,
): string | null => {
  if (global === null || slot === null) return null;
  const timestamp = numberOf(recordOf(global[slot])?.["timestamp"]);
  if (timestamp === null) return null;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

/** Summarise a decoded game save with names from System.json and the database. */
export const summariseSave = (
  value: unknown,
  base: Pick<Save, "path" | "kind" | "slot" | "format" | "bytes" | "sha256">,
  names: SaveNames,
  global: readonly unknown[] | null,
): Save => {
  const save = recordOf(value);
  const empty = {
    ...base,
    version_id: null,
    saved_at: null,
    playtime_seconds: null,
    map: null,
    gold: null,
    steps: null,
    party: [],
    items: [],
    switches_on: [],
    variables: [],
    self_switches_on: 0,
    keys: save === null ? [] : Object.keys(save),
  };
  if (save === null || base.kind !== "game") return empty;
  const system = recordOf(save["system"]);
  const party = recordOf(save["party"]);
  const mapId = idOf(recordOf(save["map"])?.["_mapId"]);
  const player = recordOf(save["player"]);
  const frames = numberOf(system?.["_framesOnSave"]);
  return {
    ...empty,
    version_id: intOf(system?.["_versionId"]),
    saved_at: savedAt(global, base.slot),
    playtime_seconds: frames === null ? null : Math.floor(frames / 60),
    map:
      mapId === null
        ? null
        : {
            id: mapId,
            name: names.maps.get(mapId) ?? null,
            x: intOf(player?.["_x"]) ?? 0,
            y: intOf(player?.["_y"]) ?? 0,
          },
    gold: numberOf(party?.["_gold"]),
    steps: numberOf(party?.["_steps"]),
    party: partyOf(save, names),
    items: itemsOf(party, names),
    switches_on: arrayOf(dataOf(save["switches"])).flatMap((on, id) =>
      on === true ? [{ id, name: nameAt(names.switches, id) }] : [],
    ),
    variables: arrayOf(dataOf(save["variables"])).flatMap((item, id) =>
      item === null || item === undefined || item === 0
        ? []
        : [{ id, name: nameAt(names.variables, id), value: scalarOf(item) }],
    ),
    self_switches_on: Object.values(
      recordOf(dataOf(save["selfSwitches"])) ?? {},
    ).filter((on) => on === true).length,
  };
};
