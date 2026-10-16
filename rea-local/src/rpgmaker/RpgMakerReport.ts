import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  RPG_MAKER_TABLES,
  type InspectRpgMakerProjectInput,
  type RpgMakerProjectReport,
} from "../domain/rpgmaker/rpgMakerProject.js";
import { inspectAsset, scanAssets, type AssetScan } from "./RpgMakerAssets.js";
import { keyBytes } from "./RpgMakerCrypto.js";
import { RpgMakerFormatError, relativeName } from "./RpgMakerFiles.js";
import { indexProject, switchRows, type ProjectIndex } from "./RpgMakerIndex.js";
import {
  arrayOf,
  idOf,
  intOf,
  stringOf,
  textOf,
  type JsonRecord,
} from "./RpgMakerJson.js";
import { dataDigest, type LoadedProject } from "./RpgMakerProject.js";
import { listSaves, readSaves } from "./RpgMakerSaveFiles.js";

type Report = RpgMakerProjectReport;
type Entry = Report["database"][number];
type View = InspectRpgMakerProjectInput["view"];

const EMPTY_PASSPHRASE = createHash("md5").update("").digest("hex");
const NOTETAG = /<([^<>:\s][^<>:]*?)(?::[^<>]*)?>/gu;
const SKIPPED_FIELDS = new Set(["id", "name", "description", "note"]);

const includes = (query: string | undefined, ...values: (string | null)[]): boolean =>
  query === undefined ||
  values.some(
    (value) => value !== null && value.toLowerCase().includes(query.toLowerCase()),
  );

const entryRow = (table: Entry["table"], entry: JsonRecord): Entry => {
  const note = textOf(entry["note"]);
  return {
    table,
    id: idOf(entry["id"]) ?? 0,
    name: stringOf(entry["name"]) ?? "",
    description: textOf(entry["description"]),
    note,
    notetags: [...new Set([...(note ?? "").matchAll(NOTETAG)].map((match) => match[1] ?? ""))],
    fields: Object.fromEntries(
      Object.entries(entry).filter(
        ([key, value]) =>
          !SKIPPED_FIELDS.has(key) &&
          (value === null || ["string", "number", "boolean"].includes(typeof value)),
      ),
    ) as Entry["fields"],
  };
};

const databaseRows = (project: LoadedProject, input: InspectRpgMakerProjectInput): Entry[] =>
  RPG_MAKER_TABLES.filter((table) => input.table === undefined || input.table === table)
    .flatMap((table) => project.tables[table].map((entry) => entryRow(table, entry)))
    .filter((row) => includes(input.query, row.name, row.description, row.note));

const pluginRows = async (
  project: LoadedProject,
  input: InspectRpgMakerProjectInput,
  page: (rows: number) => { start: number; end: number },
): Promise<{ rows: Report["plugins"]; total: number }> => {
  const matching = project.plugins.filter((plugin) =>
    includes(
      input.query,
      plugin.name,
      plugin.description,
      ...Object.entries(plugin.parameters).flat(),
    ),
  );
  const { start, end } = page(matching.length);
  const rows: Report["plugins"] = [];
  for (const plugin of matching.slice(start, end)) {
    const path = join(project.location.base, "js", "plugins", `${plugin.name}.js`);
    const present = await project.reader.exists(path);
    const file = present ? await project.reader.readData(path) : null;
    rows.push({
      ...plugin,
      parameters: { ...plugin.parameters },
      file: relativeName(project.location, path),
      present,
      bytes: file?.bytes.length ?? null,
      sha256: file?.sha256 ?? null,
    });
  }
  return { rows, total: matching.length };
};

const missingPlugins = async (project: LoadedProject): Promise<number> => {
  let missing = 0;
  for (const plugin of project.plugins)
    if (!(await project.reader.exists(join(project.location.base, "js", "plugins", `${plugin.name}.js`))))
      missing += 1;
  return missing;
};

const encryptionOf = (project: LoadedProject, scan: AssetScan): Report["encryption"] => {
  const key = textOf(project.system["encryptionKey"]);
  return {
    images: project.system["hasEncryptedImages"] === true,
    audio: project.system["hasEncryptedAudio"] === true,
    key,
    empty_passphrase: key?.toLowerCase() === EMPTY_PASSPHRASE,
    recovered_key: scan.recoveredKey,
    key_matches:
      scan.recoveredKey === null || key === null
        ? null
        : scan.recoveredKey === key.toLowerCase(),
  };
};

const startOf = (system: JsonRecord): Report["project"]["start"] => {
  const map = idOf(system["startMapId"]);
  return map === null || map === 0
    ? null
    : { map_id: map, x: intOf(system["startX"]) ?? 0, y: intOf(system["startY"]) ?? 0 };
};

const projectOf = (project: LoadedProject): Report["project"] => ({
  path: project.location.root,
  engine: project.engine,
  layout: project.location.layout,
  core_version: project.coreVersion,
  data_sha256: dataDigest(project.dataFiles),
  data_files: project.dataFiles.length,
  data_bytes: project.dataFiles.reduce((sum, file) => sum + file.bytes.length, 0),
  title: stringOf(project.system["gameTitle"]),
  locale: textOf(project.system["locale"]),
  version_id: intOf(project.system["versionId"]),
  start: startOf(project.system),
});

const namedCount = (value: unknown): number =>
  arrayOf(value).filter((name, id) => id > 0 && typeof name === "string" && name.length > 0)
    .length;

const summaryOf = async (
  project: LoadedProject,
  index: ProjectIndex,
  scan: AssetScan,
  saves: number,
): Promise<Report["summary"]> => ({
  maps: project.maps.length,
  events: index.eventCount,
  common_events: project.tables.common_events.length,
  troops: project.tables.troops.length,
  messages: index.maps.reduce((sum, map) => sum + map.messages, 0) +
    index.events.dialogue.filter((row) => row.source !== "map" && row.kind === "message").length,
  choices: index.events.dialogue.filter((row) => row.kind === "choice").length,
  switches: namedCount(project.system["switches"]),
  variables: namedCount(project.system["variables"]),
  database: RPG_MAKER_TABLES.map((table) => ({ table, count: project.tables[table].length })),
  plugins: {
    total: project.plugins.length,
    enabled: project.plugins.filter(({ status }) => status).length,
    missing: await missingPlugins(project),
  },
  assets: {
    encrypted: scan.assets.filter(({ encrypted }) => encrypted).length,
    plain: scan.assets.filter(({ encrypted }) => !encrypted).length,
    undecryptable: scan.assets.filter(
      ({ encrypted, header, signature }) =>
        encrypted && (header !== "valid" || signature === "unknown"),
    ).length,
  },
  saves,
});

const normalAsset = (path: string): string => path.replaceAll("\\", "/").replace(/^\.\//u, "");

type Rows = Pick<
  Report,
  "maps" | "dialogue" | "switches" | "database" | "plugins" | "assets" | "saves"
>;

const emptyRows = (): Rows => ({
  maps: [],
  dialogue: [],
  switches: [],
  database: [],
  plugins: [],
  assets: [],
  saves: [],
});

interface ViewContext {
  readonly project: LoadedProject;
  readonly index: ProjectIndex;
  readonly scan: AssetScan;
  readonly input: InspectRpgMakerProjectInput;
}

const filteredRows = (context: ViewContext, view: View): readonly unknown[] => {
  const { project, index, scan, input } = context;
  const { map, query } = input;
  switch (view) {
    case "maps":
      return index.maps.filter(
        (row) => (map === undefined || row.id === map) && includes(query, row.name, row.display_name),
      );
    case "dialogue":
      return index.events.dialogue.filter(
        (row) =>
          (map === undefined || (row.source === "map" && row.source_id === map)) &&
          includes(query, row.lines.join("\n"), row.speaker, row.face, row.source_name, row.event_name),
      );
    case "switches":
      return switchRows(project, index.events, map).filter((row) => includes(query, row.name));
    case "database":
      return databaseRows(project, input);
    case "assets":
      return scan.assets.filter((row) => includes(query, row.path));
    default:
      return [];
  }
};

const selectedAsset = async (context: ViewContext): Promise<Report["assets"]> => {
  const wanted = normalAsset(context.input.asset ?? "");
  const asset = context.scan.assets.find(({ path }) => path === wanted);
  if (asset === undefined)
    throw new RpgMakerFormatError(`No image, audio or movie file at ${wanted}`);
  return [
    await inspectAsset(
      context.project.reader,
      asset,
      keyBytes(textOf(context.project.system["encryptionKey"])),
    ),
  ];
};

const viewRows = async (
  context: ViewContext,
  page: (rows: number) => { start: number; end: number },
): Promise<{ rows: Rows; total: number }> => {
  const rows = emptyRows();
  const { view } = context.input;
  if (view === "plugins") {
    const plugins = await pluginRows(context.project, context.input, page);
    return { rows: { ...rows, plugins: plugins.rows }, total: plugins.total };
  }
  if (view === "saves") {
    const saves = await readSaves(context.project, context.input, page);
    return { rows: { ...rows, saves: saves.rows }, total: saves.total };
  }
  if (view === "assets" && context.input.asset !== undefined) {
    const { start, end } = page(1);
    const assets = await selectedAsset(context);
    return { rows: { ...rows, assets: start < end ? assets : [] }, total: 1 };
  }
  const matching = filteredRows(context, view);
  const { start, end } = page(matching.length);
  return { rows: { ...rows, [view]: matching.slice(start, end) }, total: matching.length };
};

/** Build the summary and one paged view of a loaded MV/MZ project. */
export const buildRpgMakerReport = async (
  project: LoadedProject,
  input: InspectRpgMakerProjectInput,
  limitations: readonly string[],
): Promise<Report> => {
  const index = indexProject(project);
  const key = keyBytes(textOf(project.system["encryptionKey"]));
  const scan = await scanAssets(project.reader, key);
  const saveFiles = await listSaves(project);
  const page = (rows: number) => {
    const start = Math.min(input.offset, rows);
    return { start, end: Math.min(rows, start + input.limit) };
  };
  const { rows, total } = await viewRows({ project, index, scan, input }, page);
  const returned = Object.values(rows).reduce((sum, list) => sum + list.length, 0);
  return {
    project: projectOf(project),
    encryption: encryptionOf(project, scan),
    summary: await summaryOf(project, index, scan, saveFiles.length),
    page: {
      view: input.view,
      map: input.map ?? null,
      table: input.table ?? null,
      asset: input.asset === undefined ? null : normalAsset(input.asset),
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total,
      returned,
    },
    ...rows,
    limitations: [
      ...limitations,
      ...project.limitations,
      ...(scan.truncated ? ["Asset folders hold more than 200,000 files; the list is truncated."] : []),
      ...(project.reader.skippedLinks > 0
        ? [`${String(project.reader.skippedLinks)} symlinks in asset or save folders were skipped, not followed.`]
        : []),
    ],
  };
};

