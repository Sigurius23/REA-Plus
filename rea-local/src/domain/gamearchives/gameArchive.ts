import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();

export const GAME_ARCHIVE_FORMATS = [
  "godot_pck",
  "renpy_rpa",
  "valve_vpk",
  "doom_wad",
] as const;

export const GAME_ARCHIVE_PAGE_LIMIT = 1000;
export const GAME_ARCHIVE_PREVIEW_LIMIT = 65_536;

export const inspectGameArchiveInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute Godot .pck (or an executable with an embedded pack), Ren'Py .rpa, Valve _dir.vpk/.vpk, or Doom IWAD/PWAD path",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Case-insensitive substring of entry paths to keep"),
  extension: z
    .string()
    .regex(/^[A-Za-z0-9_]{1,16}$/u)
    .optional()
    .describe("Keep entries with this extension, such as gd, rpyc or vmt"),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(GAME_ARCHIVE_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
  entry: z
    .string()
    .min(1)
    .max(4096)
    .optional()
    .describe(
      "Exact entry path to preview: SHA-256 of its bytes and the first preview_bytes as text or hex",
    ),
  preview_bytes: z
    .number()
    .int()
    .min(1)
    .max(GAME_ARCHIVE_PREVIEW_LIMIT)
    .default(4096)
    .describe("Bytes of the selected entry to return"),
});

export const gameArchiveEntrySchema = z.strictObject({
  path: z.string(),
  size: count.describe("Logical size of the entry's bytes."),
  offset: count
    .nullable()
    .describe("Where the entry's data starts in the selected file."),
  stored_in: z
    .string()
    .nullable()
    .describe(
      "Sibling archive holding the data (VPK chunks); null when local.",
    ),
  inline_bytes: count.describe(
    "Bytes stored inside the index itself (RPA prefixes, VPK preload data).",
  ),
  encrypted: z.boolean(),
  removed: z.boolean().describe("Godot patch entry that deletes the path."),
  group: z
    .string()
    .nullable()
    .describe("WAD map or namespace (sprites, flats, patches, ...)."),
  checksum: z
    .strictObject({
      algorithm: z.enum(["md5", "crc32"]),
      value: z.string().regex(/^[0-9a-f]{8,32}$/u),
      verified: z
        .boolean()
        .nullable()
        .describe(
          "Recomputed over the entry; null when its bytes were not read.",
        ),
    })
    .nullable(),
});

export const gameArchiveSchema = z.strictObject({
  archive: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    format: z.enum(GAME_ARCHIVE_FORMATS),
    version: z.string(),
    engine_version: z
      .string()
      .nullable()
      .describe("Godot version that wrote the pack."),
    embedded_at: count
      .nullable()
      .describe(
        "Start of a pack embedded in a larger file, such as an exported game.",
      ),
    flags: z.array(z.string()),
    entries: count,
    entry_bytes: count,
    extensions: z.array(
      z.strictObject({ extension: z.string(), entries: count, bytes: count }),
    ),
    notes: z.array(z.string()),
  }),
  page: z.strictObject({
    query: z.string().nullable(),
    extension: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  entries: z.array(gameArchiveEntrySchema),
  entry: z
    .strictObject({
      path: z.string(),
      size: count,
      available: z.boolean(),
      reason: z.string().nullable(),
      sha256: digest.nullable(),
      checksum_verified: z.boolean().nullable(),
      encoding: z.enum(["utf8", "hex"]).nullable(),
      preview: z.string().nullable(),
      truncated: z.boolean(),
    })
    .nullable(),
  limitations: z.array(z.string()),
});

export type InspectGameArchiveInput = z.output<
  typeof inspectGameArchiveInputSchema
>;
export type GameArchive = z.output<typeof gameArchiveSchema>;
export type GameArchiveEntry = z.output<typeof gameArchiveEntrySchema>;
