import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const text = z.string().nullable();
const environmentName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u);

export const GODOT_VIEWS = [
  "resources",
  "properties",
  "nodes",
  "connections",
  "source",
  "tokens",
  "values",
] as const;

export const GODOT_KINDS = ["resource", "scene", "script", "variant"] as const;

/** The view each kind of file opens with. */
export const DEFAULT_GODOT_VIEW: Readonly<
  Record<(typeof GODOT_KINDS)[number], (typeof GODOT_VIEWS)[number]>
> = {
  resource: "resources",
  scene: "nodes",
  script: "source",
  variant: "values",
};

export const GODOT_PAGE_LIMIT = 1000;

export const inspectGodotFileInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute file: a binary resource (.res, .scn), compiled script (.gdc, .gde), a save written with store_var / open_compressed / open_encrypted, or a Godot pack (.pck, or a game executable with one embedded) when entry is given",
    ),
  entry: z
    .string()
    .min(1)
    .max(1024)
    .optional()
    .describe(
      "Path inside a Godot pack, with or without res://; a .gd or .tscn path follows its .remap to the exported .gdc or .scn",
    ),
  view: z
    .enum(GODOT_VIEWS)
    .optional()
    .describe(
      "resources: the external and internal resources; properties: stored property values; nodes: the scene tree; connections: signal connections; source: GDScript rebuilt from a compiled script; tokens: its token stream; values: a store_var save's values. Defaults to the kind's natural view.",
    ),
  resource: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Internal resource id (main, or a SubResource id) whose properties to list",
    ),
  node: z
    .string()
    .min(1)
    .max(1024)
    .optional()
    .describe("Scene node path (. for the root) whose properties to list"),
  key_env: environmentName
    .optional()
    .describe(
      "Name of an environment variable holding a 64-hex-digit AES-256 key (a game's script encryption key, or an open_encrypted key) for GDEC files. The key itself is never an input.",
    ),
  password_env: environmentName
    .optional()
    .describe(
      "Name of an environment variable holding the password a game passed to open_encrypted_with_pass.",
    ),
  engine: z
    .enum(["auto", "3", "4"])
    .default("auto")
    .describe(
      "Godot major version of store_var data, whose type numbers differ between Godot 3 and 4; auto keeps the one that reads every byte.",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of names, types, paths, values or source text",
    ),
  offset: count.default(0).describe("Matching rows to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(GODOT_PAGE_LIMIT)
    .default(200)
    .describe("Matching rows to return"),
});

export const godotResourceRowSchema = z.strictObject({
  id: z.string(),
  kind: z.enum(["main", "internal", "external"]),
  type: z.string(),
  path: text,
  uid: text,
  properties: count,
  offset: count.nullable(),
  error: text,
});

export const godotPropertyRowSchema = z.strictObject({
  owner_kind: z.enum(["resource", "node"]),
  owner: z.string(),
  name: z.string(),
  type: z.string(),
  value: z.string().describe("As Godot's text resource format writes it."),
  truncated: z.boolean(),
});

export const godotNodeRowSchema = z.strictObject({
  index: count,
  path: z.string(),
  parent: text,
  type: text.describe(
    "Null for an instanced scene, whose root type is its own.",
  ),
  instance: text,
  placeholder: z.boolean(),
  groups: z.array(z.string()),
  properties: count,
});

export const godotConnectionRowSchema = z.strictObject({
  from: z.string(),
  signal: z.string(),
  to: z.string(),
  method: z.string(),
  flags: z.array(z.string()),
  binds: z.array(z.string()),
  unbinds: count,
});

export const godotSourceRowSchema = z.strictObject({
  line: count,
  text: z.string(),
});

export const godotTokenRowSchema = z.strictObject({
  index: count,
  line: count.nullable(),
  type: z.string(),
  text: z.string(),
});

export const godotValueRowSchema = z.strictObject({
  path: z.string(),
  depth: count,
  type: z.string(),
  value: text.describe(
    "The value in Godot's text notation; containers are cut at 1000 characters and list their children as rows of their own.",
  ),
  truncated: z.boolean(),
  children: count,
});

export const godotFileSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
  }),
  entry: z
    .strictObject({
      path: z.string(),
      remapped_from: text,
      offset: count,
      bytes: count,
      pack_engine: text,
    })
    .nullable(),
  layers: z.array(
    z.strictObject({
      kind: z.enum(["decrypted", "decompressed"]),
      format: z.string(),
      input_bytes: count,
      output_bytes: count,
    }),
  ),
  kind: z.enum(GODOT_KINDS),
  resource: z
    .strictObject({
      engine: z.string(),
      format: count,
      type: z.string(),
      uid: text,
      script_class: text,
      big_endian: z.boolean(),
      real64: z.boolean(),
      flags: z.array(z.string()),
      external: count,
      internal: count,
      trailer: z
        .boolean()
        .describe("Whether the file ends with RSRC, as Godot writes it."),
    })
    .nullable(),
  script: z
    .strictObject({
      version: count,
      engine: z.string(),
      compressed: z.boolean(),
      identifiers: count,
      constants: count,
      tokens: count,
    })
    .nullable(),
  variant: z
    .strictObject({
      engine: z.enum(["3", "4"]),
      values: count,
      encoding: z
        .enum(["store_var", "var_to_bytes", "project_settings"])
        .describe(
          "store_var writes a length before each value; var_to_bytes does not; project_settings is project.binary (ECFG), read as one dictionary.",
        ),
      also_reads_as: z.enum(["3", "4"]).nullable(),
    })
    .nullable(),
  summary: z.strictObject({
    resources: count,
    properties: count,
    nodes: count,
    connections: count,
    lines: count,
    tokens: count,
    values: count,
    errors: count,
  }),
  page: z.strictObject({
    view: z.enum(GODOT_VIEWS),
    resource: text,
    node: text,
    query: text,
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  resources: z.array(godotResourceRowSchema),
  properties: z.array(godotPropertyRowSchema),
  nodes: z.array(godotNodeRowSchema),
  connections: z.array(godotConnectionRowSchema),
  source: z.array(godotSourceRowSchema),
  tokens: z.array(godotTokenRowSchema),
  values: z.array(godotValueRowSchema),
  limitations: z.array(z.string()),
});

export type InspectGodotFileInput = z.output<
  typeof inspectGodotFileInputSchema
>;
export type GodotFileReport = z.output<typeof godotFileSchema>;
