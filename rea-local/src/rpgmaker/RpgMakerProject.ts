import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  RPG_MAKER_TABLES,
  type RpgMakerTable,
} from "../domain/rpgmaker/rpgMakerProject.js";
import {
  ProjectReader,
  RpgMakerFormatError,
  type ProjectLocation,
  type ReadFile,
} from "./RpgMakerFiles.js";
import {
  arrayOf,
  entriesOf,
  idOf,
  recordOf,
  stringOf,
  type JsonRecord,
} from "./RpgMakerJson.js";

const TABLE_FILES: Readonly<Record<RpgMakerTable, string>> = {
  actors: "Actors.json",
  classes: "Classes.json",
  skills: "Skills.json",
  items: "Items.json",
  weapons: "Weapons.json",
  armors: "Armors.json",
  enemies: "Enemies.json",
  troops: "Troops.json",
  states: "States.json",
  animations: "Animations.json",
  tilesets: "Tilesets.json",
  common_events: "CommonEvents.json",
};

export interface PluginEntry {
  readonly name: string;
  readonly status: boolean;
  readonly description: string;
  readonly parameters: Readonly<Record<string, string>>;
}

export interface MapEntry {
  readonly id: number;
  readonly info: JsonRecord;
  readonly data: JsonRecord | null;
}

export interface LoadedProject {
  readonly location: ProjectLocation;
  readonly reader: ProjectReader;
  readonly engine: "mv" | "mz";
  readonly coreVersion: string | null;
  readonly system: JsonRecord;
  readonly maps: readonly MapEntry[];
  readonly tables: Readonly<Record<RpgMakerTable, readonly JsonRecord[]>>;
  readonly plugins: readonly PluginEntry[];
  readonly dataFiles: readonly ReadFile[];
  readonly limitations: readonly string[];
}

/** var $plugins = [...]; is data the editor writes; it is parsed, never run. */
export const parsePluginList = (text: string): PluginEntry[] => {
  const marker = text.indexOf("$plugins");
  const start = text.indexOf("[", marker < 0 ? 0 : marker);
  const end = text.lastIndexOf("]");
  if (marker < 0 || start < 0 || end < start)
    throw new RpgMakerFormatError("js/plugins.js has no $plugins list");
  let list: unknown;
  try {
    list = JSON.parse(text.slice(start, end + 1));
  } catch (cause) {
    throw new RpgMakerFormatError(
      "js/plugins.js is not the editor's JSON plugin list",
      { cause },
    );
  }
  return arrayOf(list).flatMap((value) => {
    const entry = recordOf(value);
    const name = stringOf(entry?.["name"]);
    if (entry === null || name === null) return [];
    const parameters = Object.fromEntries(
      Object.entries(recordOf(entry["parameters"]) ?? {}).map(
        ([key, parameter]) => [
          key,
          typeof parameter === "string" ? parameter : JSON.stringify(parameter),
        ],
      ),
    );
    return [
      {
        name,
        status: entry["status"] === true,
        description: stringOf(entry["description"]) ?? "",
        parameters,
      },
    ];
  });
};

const CORE_FILES = [
  ["rmmz_core.js", "mz"],
  ["rpg_core.js", "mv"],
] as const;

const coreScript = async (
  reader: ProjectReader,
  base: string,
  system: JsonRecord,
): Promise<{ engine: "mv" | "mz"; version: string | null }> => {
  for (const [name, engine] of CORE_FILES) {
    const path = join(base, "js", name);
    if (!(await reader.exists(path))) continue;
    const head = (await reader.head(path, 512)).toString("utf8");
    const version = /v(\d+\.\d+\.\d+)/u.exec(head)?.[1] ?? null;
    return { engine, version };
  }
  return { engine: "advanced" in system ? "mz" : "mv", version: null };
};

const mapName = (id: number): string =>
  `Map${String(id).padStart(3, "0")}.json`;

const loadMaps = async (
  reader: ProjectReader,
  data: string,
  infos: unknown,
  files: ReadFile[],
): Promise<MapEntry[]> => {
  const maps: MapEntry[] = [];
  for (const info of entriesOf(infos)) {
    const id = idOf(info["id"]) ?? 0;
    const path = join(data, mapName(id));
    if (!(await reader.exists(path))) {
      maps.push({ id, info, data: null });
      continue;
    }
    const { file, value } = await reader.readJson(path);
    files.push(file);
    maps.push({ id, info, data: recordOf(value) });
  }
  return maps;
};

const loadTables = async (
  reader: ProjectReader,
  data: string,
  files: ReadFile[],
  limitations: string[],
): Promise<Record<RpgMakerTable, readonly JsonRecord[]>> => {
  const tables = {} as Record<RpgMakerTable, readonly JsonRecord[]>;
  for (const table of RPG_MAKER_TABLES) {
    const path = join(data, TABLE_FILES[table]);
    if (!(await reader.exists(path))) {
      limitations.push(`data/${TABLE_FILES[table]} is missing.`);
      tables[table] = [];
      continue;
    }
    const { file, value } = await reader.readJson(path);
    files.push(file);
    tables[table] = entriesOf(value);
  }
  return tables;
};

const loadPlugins = async (
  reader: ProjectReader,
  base: string,
  limitations: string[],
): Promise<PluginEntry[]> => {
  const path = join(base, "js", "plugins.js");
  if (!(await reader.exists(path))) return [];
  const file = await reader.readData(path);
  try {
    return parsePluginList(file.bytes.toString("utf8"));
  } catch (cause) {
    limitations.push(
      cause instanceof Error ? cause.message : "js/plugins.js is unreadable",
    );
    return [];
  }
};

/** Read System, MapInfos, every map, the database and the plugin list. */
export const loadProject = async (
  location: ProjectLocation,
  signal: AbortSignal | undefined,
): Promise<LoadedProject> => {
  const reader = new ProjectReader(location, signal);
  const data = join(location.base, "data");
  const files: ReadFile[] = [];
  const limitations: string[] = [];
  const system = await reader.readJson(join(data, "System.json"));
  files.push(system.file);
  const systemRecord = recordOf(system.value);
  if (systemRecord === null)
    throw new RpgMakerFormatError("data/System.json is not an object");
  const infos = await reader.readJson(join(data, "MapInfos.json"));
  files.push(infos.file);
  const maps = await loadMaps(reader, data, infos.value, files);
  const tables = await loadTables(reader, data, files, limitations);
  const plugins = await loadPlugins(reader, location.base, limitations);
  const core = await coreScript(reader, location.base, systemRecord);
  return {
    location,
    reader,
    engine: core.engine,
    coreVersion: core.version,
    system: systemRecord,
    maps,
    tables,
    plugins,
    dataFiles: files,
    limitations,
  };
};

/** Digest over the data files read, so the Evidence names exact game data. */
export const dataDigest = (files: readonly ReadFile[]): string => {
  const hash = createHash("sha256");
  for (const file of [...files].sort((left, right) =>
    left.path < right.path ? -1 : 1,
  ))
    hash.update(`${file.path}\0${file.sha256}\n`);
  return hash.digest("hex");
};
