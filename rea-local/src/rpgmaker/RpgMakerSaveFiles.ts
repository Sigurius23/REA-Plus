import { basename, join } from "node:path";

import type {
  InspectRpgMakerProjectInput,
  RpgMakerProjectReport,
} from "../domain/rpgmaker/rpgMakerProject.js";
import { relativeName } from "./RpgMakerFiles.js";
import { arrayOf, idOf, stringOf } from "./RpgMakerJson.js";
import type { LoadedProject } from "./RpgMakerProject.js";
import {
  decodeSave,
  SAVE_NAME,
  summariseSave,
  type SaveNames,
} from "./RpgMakerSaves.js";

type Save = RpgMakerProjectReport["saves"][number];
const MAX_SAVE_BYTES = 32 * 1024 * 1024;

interface SaveFile {
  readonly path: string;
  readonly name: string;
  readonly kind: Save["kind"];
  readonly slot: number | null;
  readonly format: Save["format"];
}

/** Save files in the folder the engine writes to: save/ beside index.html. */
export const listSaves = async (
  project: LoadedProject,
): Promise<SaveFile[]> => {
  const { files } = await project.reader.walk(
    join(project.location.base, "save"),
  );
  return files.flatMap(({ path }) => {
    const name = basename(path);
    const match = SAVE_NAME.exec(name);
    if (match === null) return [];
    const slot = match[2] === undefined ? null : Number(match[2]);
    return [
      {
        path,
        name,
        kind: slot !== null ? "game" : (match[1] as "global" | "config"),
        slot,
        format: match[3] === "rpgsave" ? "lz-string" : "zlib",
      },
    ];
  });
};

const namesOf = (project: LoadedProject): SaveNames => {
  const names = (table: keyof LoadedProject["tables"]) =>
    new Map(
      project.tables[table].map((entry) => [
        idOf(entry["id"]) ?? 0,
        stringOf(entry["name"]) ?? "",
      ]),
    );
  return {
    switches: arrayOf(project.system["switches"]),
    variables: arrayOf(project.system["variables"]),
    maps: new Map(
      project.maps.map((map) => [map.id, stringOf(map.info["name"])]),
    ),
    actors: names("actors"),
    items: {
      item: names("items"),
      weapon: names("weapons"),
      armor: names("armors"),
    },
  };
};

const globalOf = async (
  project: LoadedProject,
  files: readonly SaveFile[],
): Promise<readonly unknown[] | null> => {
  const global = files.find(({ kind }) => kind === "global");
  if (global === undefined) return null;
  try {
    const value = decodeSave(
      await project.reader.readWhole(global.path, MAX_SAVE_BYTES),
      global.format,
    );
    return Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
};

/** Decode the saves on the requested page; the global save supplies timestamps. */
export const readSaves = async (
  project: LoadedProject,
  input: InspectRpgMakerProjectInput,
  page: (rows: number) => { start: number; end: number },
): Promise<{ rows: Save[]; total: number }> => {
  const files = await listSaves(project);
  const query = input.query?.toLowerCase();
  const matching = files.filter(
    ({ path }) =>
      query === undefined ||
      relativeName(project.location, path).toLowerCase().includes(query),
  );
  const { start, end } = page(matching.length);
  const names = namesOf(project);
  const global = await globalOf(project, files);
  const rows: Save[] = [];
  for (const file of matching.slice(start, end)) {
    const read = await project.reader.readWhole(file.path, MAX_SAVE_BYTES);
    rows.push(
      summariseSave(
        decodeSave(read, file.format),
        {
          path: read.path,
          kind: file.kind,
          slot: file.slot,
          format: file.format,
          bytes: read.bytes.length,
          sha256: read.sha256,
        },
        names,
        global,
      ),
    );
  }
  return { rows, total: matching.length };
};
