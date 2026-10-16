import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const line = z.number().int().nonnegative().nullable();

export const RENPY_SCRIPT_VIEWS = [
  "labels",
  "dialogue",
  "menus",
  "definitions",
  "translations",
] as const;

export const RENPY_SCRIPT_PAGE_LIMIT = 1000;

export const inspectRenpyScriptInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe("Absolute compiled Ren'Py script (.rpyc) path"),
  view: z
    .enum(RENPY_SCRIPT_VIEWS)
    .default("labels")
    .describe(
      "labels: labels with jumps, calls and counts; dialogue: say statements with speakers and translation identifiers; menus: choices with conditions and targets; definitions: define, default, image, screen, transform and style names; translations: translate blocks and strings.",
    ),
  label: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Keep dialogue and menus under this label only"),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of label names, dialogue text or speakers, menu choices, definition names or values, or translation text",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(RENPY_SCRIPT_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

const located = {
  file: z.string().nullable().describe("Source .rpy path recorded by Ren'Py."),
  line,
};

export const renpyLabelSchema = z.strictObject({
  name: z.string(),
  ...located,
  statements: count,
  dialogue: count,
  menus: count,
  jumps: z.array(z.string()),
  calls: z.array(z.string()),
});

export const renpyDialogueSchema = z.strictObject({
  label: z.string().nullable(),
  ...located,
  who: z
    .string()
    .nullable()
    .describe(
      "Speaker as written: a character variable, or null for narration.",
    ),
  what: z.string().describe("Text as written in the script, tags included."),
  identifier: z
    .string()
    .nullable()
    .describe(
      "Translation identifier, as `translate <language> <identifier>:` uses.",
    ),
  language: z
    .string()
    .nullable()
    .describe("Translation language; null for the original script."),
});

export const renpyMenuSchema = z.strictObject({
  label: z.string().nullable(),
  ...located,
  caption: z.string().nullable(),
  choices: z.array(
    z.strictObject({
      text: z.string(),
      condition: z.string().nullable(),
      jumps: z.array(z.string()),
      calls: z.array(z.string()),
    }),
  ),
});

export const renpyDefinitionSchema = z.strictObject({
  kind: z.enum(["define", "default", "image", "screen", "transform", "style"]),
  name: z.string(),
  store: z.string().nullable(),
  value: z.string().nullable().describe("Python source of the value."),
  ...located,
});

export const renpyTranslationSchema = z.strictObject({
  kind: z.enum(["string", "block"]),
  language: z.string().nullable(),
  identifier: z.string().nullable(),
  old: z.string().nullable(),
  new: z.string().nullable(),
  ...located,
});

export const renpyScriptSchema = z.strictObject({
  script: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    format: z.enum(["rpyc2", "rpyc1"]),
    slot: z
      .number()
      .int()
      .nullable()
      .describe("RPC2 slot read: 2 after Ren'Py's static transforms, else 1."),
    script_version: z.number().int().nullable(),
    source_files: z.array(z.string()),
    statements: count,
    statement_kinds: z.array(z.strictObject({ kind: z.string(), count })),
  }),
  summary: z.strictObject({
    labels: count,
    dialogue: count,
    menus: count,
    definitions: count,
    translations: count,
    languages: z.array(z.string()),
    speakers: z.array(
      z.strictObject({ who: z.string().nullable(), lines: count }),
    ),
  }),
  page: z.strictObject({
    view: z.enum(RENPY_SCRIPT_VIEWS),
    label: z.string().nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  labels: z.array(renpyLabelSchema),
  dialogue: z.array(renpyDialogueSchema),
  menus: z.array(renpyMenuSchema),
  definitions: z.array(renpyDefinitionSchema),
  translations: z.array(renpyTranslationSchema),
  limitations: z.array(z.string()),
});

export type InspectRenpyScriptInput = z.output<
  typeof inspectRenpyScriptInputSchema
>;
export type RenpyScriptReport = z.output<typeof renpyScriptSchema>;
