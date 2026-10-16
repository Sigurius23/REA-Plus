import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export const RPG_MAKER_VIEWS = [
  "maps",
  "dialogue",
  "switches",
  "database",
  "plugins",
  "assets",
  "saves",
] as const;

export const RPG_MAKER_TABLES = [
  "actors",
  "classes",
  "skills",
  "items",
  "weapons",
  "armors",
  "enemies",
  "troops",
  "states",
  "animations",
  "tilesets",
  "common_events",
] as const;

export const RPG_MAKER_PAGE_LIMIT = 1000;

export const inspectRpgMakerProjectInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute RPG Maker MV/MZ game or project directory: the folder holding data/ (MZ, MV projects) or www/data/ (deployed MV), or the www folder itself",
    ),
  view: z
    .enum(RPG_MAKER_VIEWS)
    .default("maps")
    .describe(
      "maps: maps with events, dialogue counts, transfers and common-event calls; dialogue: Show Text, Show Choices, scrolling text and comments with speaker and face; switches: named switches and variables with the events that read and write them; database: actors, items, skills and the other tables with notes and notetags; plugins: plugins.js entries with parameters and their script files; assets: encrypted and plain images and audio with key verification; saves: decoded save files with party, gold, items, switches and variables.",
    ),
  map: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("Keep maps, dialogue and switch sites of this map id only"),
  table: z
    .enum(RPG_MAKER_TABLES)
    .optional()
    .describe("Database table for the database view (default: every table)"),
  asset: z
    .string()
    .min(1)
    .max(1024)
    .optional()
    .describe(
      "One asset path relative to the game folder (img/faces/Actor1.png_): the assets view then decrypts it fully and reports its digest and image size",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of map, event, switch, variable, entry, plugin or asset names, dialogue text, notes or plugin parameters",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(RPG_MAKER_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

const source = {
  source: z.enum(["map", "common_event", "troop"]),
  source_id: count,
  source_name: z.string().nullable(),
  event_id: count.nullable().describe("Map event id; null outside maps."),
  event_name: z.string().nullable(),
  page: count.nullable().describe("1-based event or troop page."),
  index: count.describe("Command index in the page's list."),
};

export const rpgMakerMapSchema = z.strictObject({
  id: count,
  name: z.string().nullable().describe("Editor name from MapInfos.json."),
  display_name: z.string().nullable(),
  parent_id: count.nullable(),
  order: z.number().int().nullable(),
  present: z.boolean().describe("Whether data/MapNNN.json exists."),
  width: count.nullable(),
  height: count.nullable(),
  tileset_id: count.nullable(),
  bgm: z.string().nullable(),
  events: count,
  pages: count,
  commands: count,
  messages: count,
  choices: count,
  transfers: z
    .array(count)
    .describe("Maps reached by Transfer Player with a direct destination."),
  common_events: z.array(count).describe("Common events called."),
});

export const rpgMakerDialogueSchema = z.strictObject({
  ...source,
  kind: z.enum(["message", "choice", "scrolling", "comment"]),
  speaker: z
    .string()
    .nullable()
    .describe("MZ Show Text name box; null when empty or on MV."),
  face: z
    .string()
    .nullable()
    .describe("Face image and index, as faceName:index."),
  lines: z
    .array(z.string())
    .describe(
      "Text lines as written, escape codes such as \\N[1] kept; the choice texts for a choice.",
    ),
});

export const rpgMakerSiteSchema = z.strictObject({
  ...source,
  access: z.enum(["read", "write"]),
  command: z
    .number()
    .int()
    .nullable()
    .describe("Event command code; null for a page or trigger condition."),
});

export const rpgMakerSwitchSchema = z.strictObject({
  kind: z.enum(["switch", "variable"]),
  id: count,
  name: z.string(),
  reads: count,
  writes: count,
  sites: z.array(rpgMakerSiteSchema).describe("At most 20 sites."),
});

export const rpgMakerEntrySchema = z.strictObject({
  table: z.enum(RPG_MAKER_TABLES),
  id: count,
  name: z.string(),
  description: z.string().nullable(),
  note: z.string().nullable(),
  notetags: z.array(z.string()).describe("Tag names found in the note."),
  fields: z
    .record(z.string(), scalar)
    .describe("The entry's other top-level scalar fields."),
});

export const rpgMakerPluginSchema = z.strictObject({
  name: z.string(),
  status: z.boolean(),
  description: z.string(),
  parameters: z.record(z.string(), z.string()),
  file: z.string().describe("Script path relative to the game folder."),
  present: z.boolean(),
  bytes: count.nullable(),
  sha256: digest.nullable(),
});

export const rpgMakerAssetSchema = z.strictObject({
  path: z.string().describe("Path relative to the game folder."),
  kind: z.enum(["image", "audio", "video", "other"]),
  encrypted: z.boolean(),
  decrypted_path: z
    .string()
    .nullable()
    .describe("Name the engine requests (.png for .rpgmvp or .png_)."),
  bytes: count,
  header: z
    .enum(["valid", "invalid"])
    .nullable()
    .describe("RPGMV header check for encrypted files."),
  signature: z
    .enum(["png", "ogg", "m4a", "webm", "mp4", "unknown"])
    .describe("File type after decryption with the System.json key."),
  sha256: digest
    .nullable()
    .describe("Digest of the decrypted bytes; only for the selected asset."),
  image: z
    .strictObject({ width: count, height: count })
    .nullable()
    .describe("PNG size; only for the selected asset."),
});

const named = z.strictObject({ id: count, name: z.string().nullable() });

export const rpgMakerSaveSchema = z.strictObject({
  path: z.string().describe("Path relative to the game folder."),
  kind: z.enum(["game", "global", "config"]),
  slot: count.nullable(),
  format: z.enum(["lz-string", "zlib"]),
  bytes: count,
  sha256: digest,
  version_id: z
    .number()
    .int()
    .nullable()
    .describe("Game_System version id; compare with System.json versionId."),
  saved_at: z.string().nullable().describe("ISO time from the global save."),
  playtime_seconds: count.nullable(),
  map: z
    .strictObject({
      id: count,
      name: z.string().nullable(),
      x: z.number().int(),
      y: z.number().int(),
    })
    .nullable(),
  gold: z.number().nullable(),
  steps: z.number().nullable(),
  party: z.array(
    z.strictObject({
      actor_id: count,
      name: z.string().nullable(),
      level: z.number().int().nullable(),
      hp: z.number().nullable(),
      mp: z.number().nullable(),
    }),
  ),
  items: z.array(
    z.strictObject({
      kind: z.enum(["item", "weapon", "armor"]),
      id: count,
      name: z.string().nullable(),
      count: z.number(),
    }),
  ),
  switches_on: z.array(named),
  variables: z.array(
    z.strictObject({
      id: count,
      name: z.string().nullable(),
      value: scalar,
    }),
  ),
  self_switches_on: count,
  keys: z
    .array(z.string())
    .describe("Top-level keys of the decoded save object."),
});

export const rpgMakerProjectSchema = z.strictObject({
  project: z.strictObject({
    path: z.string().min(1),
    engine: z.enum(["mv", "mz"]),
    layout: z
      .enum(["deployed-www", "root"])
      .describe("deployed-www: MV's www/ folder; root: data/ at the top."),
    core_version: z
      .string()
      .nullable()
      .describe("Version in the rpg_core.js or rmmz_core.js header."),
    data_sha256: digest.describe(
      "SHA-256 over the sorted data file paths and their SHA-256 digests.",
    ),
    data_files: count,
    data_bytes: count,
    title: z.string().nullable(),
    locale: z.string().nullable(),
    version_id: z.number().int().nullable(),
    start: z
      .strictObject({ map_id: count, x: z.number().int(), y: z.number().int() })
      .nullable(),
  }),
  encryption: z.strictObject({
    images: z.boolean(),
    audio: z.boolean(),
    key: z
      .string()
      .nullable()
      .describe("System.json encryptionKey: 16 bytes as hex."),
    empty_passphrase: z
      .boolean()
      .describe("The key is the MD5 of an empty string."),
    recovered_key: z
      .string()
      .nullable()
      .describe(
        "Key recovered from an encrypted PNG, whose first 16 bytes are fixed.",
      ),
    key_matches: z
      .boolean()
      .nullable()
      .describe("Whether the recovered key equals the System.json key."),
  }),
  summary: z.strictObject({
    maps: count,
    events: count,
    common_events: count,
    troops: count,
    messages: count,
    choices: count,
    switches: count.describe("Named switches."),
    variables: count.describe("Named variables."),
    database: z.array(
      z.strictObject({ table: z.enum(RPG_MAKER_TABLES), count }),
    ),
    plugins: z.strictObject({ total: count, enabled: count, missing: count }),
    assets: z.strictObject({
      encrypted: count,
      plain: count,
      undecryptable: count,
    }),
    saves: count,
  }),
  page: z.strictObject({
    view: z.enum(RPG_MAKER_VIEWS),
    map: count.nullable(),
    table: z.enum(RPG_MAKER_TABLES).nullable(),
    asset: z.string().nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  maps: z.array(rpgMakerMapSchema),
  dialogue: z.array(rpgMakerDialogueSchema),
  switches: z.array(rpgMakerSwitchSchema),
  database: z.array(rpgMakerEntrySchema),
  plugins: z.array(rpgMakerPluginSchema),
  assets: z.array(rpgMakerAssetSchema),
  saves: z.array(rpgMakerSaveSchema),
  limitations: z.array(z.string()),
});

export type InspectRpgMakerProjectInput = z.output<
  typeof inspectRpgMakerProjectInputSchema
>;
export type RpgMakerProjectReport = z.output<typeof rpgMakerProjectSchema>;
export type RpgMakerTable = (typeof RPG_MAKER_TABLES)[number];
