import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export const GAMEMAKER_VIEWS = [
  "chunks",
  "resources",
  "code",
  "strings",
  "symbols",
  "textures",
  "audio",
] as const;

export const GAMEMAKER_RESOURCE_KINDS = [
  "sound",
  "audio_group",
  "sprite",
  "background",
  "path",
  "script",
  "shader",
  "font",
  "timeline",
  "object",
  "room",
  "extension",
  "texture_group",
  "animation_curve",
  "sequence",
  "particle_system",
  "particle_emitter",
] as const;

export const GAMEMAKER_PAGE_LIMIT = 1000;

export const inspectGameMakerDataInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute GameMaker data file: data.win (Windows), game.unx (Linux), game.droid (Android), game.ios, an audiogroupN.dat, or a runner executable with the data appended",
    ),
  view: z
    .enum(GAMEMAKER_VIEWS)
    .default("chunks")
    .describe(
      "chunks: the IFF chunk table; resources: sprites, objects, rooms, sounds, scripts and the other named resources with key fields; code: GML bytecode entries with sizes, locals and arguments; strings: the string table; symbols: functions and variables the bytecode references; textures: texture pages with format and size; audio: embedded audio with format and the sounds that use it.",
    ),
  kind: z
    .enum(GAMEMAKER_RESOURCE_KINDS)
    .optional()
    .describe("Resource kind for the resources view (default: every kind)"),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of chunk, resource, code, function or variable names, or string text",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(GAMEMAKER_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

export const gameMakerChunkSchema = z.strictObject({
  name: z.string(),
  offset: count.describe("File offset of the chunk header."),
  size: count,
  entries: count.nullable().describe("Entries in the chunk's pointer list."),
});

export const gameMakerResourceSchema = z.strictObject({
  kind: z.enum(GAMEMAKER_RESOURCE_KINDS),
  index: count,
  name: z.string().nullable(),
  offset: count,
  fields: z
    .record(z.string(), scalar)
    .describe("Fields whose layout is stable across GameMaker versions."),
});

export const gameMakerCodeSchema = z.strictObject({
  index: count,
  name: z.string().nullable(),
  length: count.describe("Bytecode length in bytes."),
  locals: count.nullable(),
  arguments: count.nullable(),
  bytecode_offset: count.nullable(),
  shared: z
    .boolean()
    .describe("Shares its bytecode with an earlier entry (GMS 2.3 functions)."),
});

export const gameMakerStringSchema = z.strictObject({
  index: count,
  offset: count.describe("Offset of the text, which references point at."),
  text: z.string(),
});

export const gameMakerSymbolSchema = z.strictObject({
  kind: z.enum(["function", "variable"]),
  index: count,
  name: z.string().nullable(),
  occurrences: count,
  instance_type: z
    .number()
    .int()
    .nullable()
    .describe("Variables: self -1, other -2, all -3, global -5, local -7."),
  variable_id: z.number().int().nullable(),
});

export const gameMakerTextureSchema = z.strictObject({
  index: count,
  offset: count.nullable().describe("Blob offset; null when external."),
  span: count
    .nullable()
    .describe("Bytes until the next blob or the chunk end (an upper bound)."),
  format: z.enum(["png", "qoi", "bz2-qoi", "external", "unknown"]),
  width: count.nullable(),
  height: count.nullable(),
});

export const gameMakerAudioSchema = z.strictObject({
  index: count,
  offset: count,
  bytes: count,
  format: z
    .enum(["wav", "ogg", "empty", "unknown"])
    .describe(
      "empty: a zero-filled placeholder the build left for missing audio.",
    ),
  sounds: z
    .array(z.string())
    .describe("Sounds in the default audio group that play this entry."),
});

export const gameMakerDataSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    form_offset: count.describe("0, or where an appended FORM starts."),
    form_size: count,
  }),
  general: z
    .strictObject({
      name: z.string().nullable(),
      display_name: z.string().nullable(),
      file_name: z.string().nullable(),
      config: z.string().nullable(),
      game_id: count,
      bytecode_version: count,
      stored_version: z
        .string()
        .describe(
          "GEN8 version; GameMaker Studio 2 and later always store 2.0.0.0.",
        ),
      minimum_version: z
        .string()
        .nullable()
        .describe(
          "Lowest runtime the chunk set implies (SEQN: 2.3, FEAT: 2022.8, …).",
        ),
      compiled: z
        .enum(["vm", "yyc"])
        .describe("yyc: native code, no GML bytecode in the file."),
      debugger_disabled: z.boolean(),
      window: z.strictObject({ width: count, height: count }),
      flags: z.array(z.string()),
      built_at: z.string().nullable().describe("GEN8 timestamp as ISO time."),
      steam_app_id: z.number().int(),
      room_order: count,
    })
    .nullable()
    .describe("GEN8; null for an audiogroupN.dat, which holds only AUDO."),
  summary: z.strictObject({
    chunks: count,
    resources: z.array(
      z.strictObject({ kind: z.enum(GAMEMAKER_RESOURCE_KINDS), count }),
    ),
    code: count,
    strings: count,
    functions: count,
    variables: count,
    textures: count,
    audio: count,
  }),
  page: z.strictObject({
    view: z.enum(GAMEMAKER_VIEWS),
    kind: z.enum(GAMEMAKER_RESOURCE_KINDS).nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  chunks: z.array(gameMakerChunkSchema),
  resources: z.array(gameMakerResourceSchema),
  code: z.array(gameMakerCodeSchema),
  strings: z.array(gameMakerStringSchema),
  symbols: z.array(gameMakerSymbolSchema),
  textures: z.array(gameMakerTextureSchema),
  audio: z.array(gameMakerAudioSchema),
  limitations: z.array(z.string()),
});

export type InspectGameMakerDataInput = z.output<
  typeof inspectGameMakerDataInputSchema
>;
export type GameMakerDataReport = z.output<typeof gameMakerDataSchema>;
export type GameMakerResourceKind = (typeof GAMEMAKER_RESOURCE_KINDS)[number];
