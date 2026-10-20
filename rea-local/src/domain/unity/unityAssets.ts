import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
/** Unity path IDs are signed 64-bit; JSON carries them as decimal text. */
const pathId = z.string().regex(/^-?\d{1,20}$/);
const compression = z.enum([
  "none",
  "lzma",
  "lz4",
  "lz4hc",
  "lzham",
  "unknown",
]);

/** Paged views over one bundle or serialized file; each call returns one. */
export const UNITY_ASSET_VIEWS = ["objects", "container", "scripts"] as const;

export const UNITY_ASSET_PAGE_LIMIT = 1000;

export const inspectUnityAssetsInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute UnityFS asset bundle, or a serialized file such as level0, sharedassets0.assets, resources.assets or globalgamemanagers",
    ),
  view: z
    .enum(UNITY_ASSET_VIEWS)
    .default("objects")
    .describe(
      "objects: object table with names, owners and script references; container: asset paths from AssetBundle and ResourceManager containers; scripts: MonoScripts and the MonoBehaviours that use them.",
    ),
  class_name: z
    .string()
    .regex(/^[A-Za-z0-9_]{1,64}$/u)
    .optional()
    .describe(
      "Exact class to keep, such as Texture2D or MonoBehaviour (case-insensitive); objects and container views.",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring filter: object, owner or script names; container asset paths; script class, namespace or assembly.",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(UNITY_ASSET_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

const scriptReference = z.strictObject({
  file_id: z.number().int(),
  path_id: pathId,
  file: z
    .string()
    .nullable()
    .describe("External file holding the MonoScript; null when local."),
  class_name: z.string().nullable(),
  namespace: z.string().nullable(),
  assembly: z.string().nullable(),
});

export const unityObjectSchema = z.strictObject({
  file: z.string().describe("Serialized file holding the object."),
  path_id: pathId,
  class_id: z.number().int(),
  class_name: z.string().nullable(),
  byte_start: count.describe("Offset from the start of the serialized file."),
  byte_size: count,
  name: z
    .string()
    .nullable()
    .describe("m_Name; null when the class has none or it could not be read."),
  game_object: z
    .strictObject({ path_id: pathId, name: z.string().nullable() })
    .nullable()
    .describe("Owning GameObject of a component in the same file."),
  script: scriptReference.nullable().describe("MonoBehaviour m_Script."),
});

export const unityContainerEntrySchema = z.strictObject({
  source: z.enum(["asset_bundle", "resource_manager"]),
  file: z.string(),
  asset_path: z
    .string()
    .describe("Project path for bundles, Resources.Load path for resources."),
  file_id: z.number().int(),
  path_id: pathId,
  target_file: z
    .string()
    .nullable()
    .describe("External file holding the asset; null when local."),
  class_name: z.string().nullable(),
  name: z.string().nullable(),
  preload_index: z.number().int().nullable(),
  preload_size: z.number().int().nullable(),
});

export const unityScriptSchema = z.strictObject({
  file: z
    .string()
    .describe("File holding the MonoScript, or the external path referenced."),
  path_id: pathId,
  local: z.boolean().describe("MonoScript object is in the inspected data."),
  class_name: z.string().nullable(),
  namespace: z.string().nullable(),
  assembly: z.string().nullable(),
  behaviours: count.describe("MonoBehaviours here that use this script."),
});

export const unitySerializedFileSchema = z.strictObject({
  name: z.string(),
  format_version: count,
  unity_version: z.string(),
  target_platform: z.strictObject({
    id: z.number().int().nullable(),
    name: z.string().nullable(),
  }),
  big_endian: z.boolean(),
  type_tree: z
    .boolean()
    .describe("Type trees present; player builds usually omit them."),
  objects: count,
  types: z.array(
    z.strictObject({
      class_id: z.number().int(),
      class_name: z.string().nullable(),
      script_type_index: z.number().int(),
      stripped: z.boolean().nullable(),
      objects: count,
    }),
  ),
  types_truncated: z.boolean(),
  externals: z.array(
    z.strictObject({
      file_id: z.number().int().positive(),
      path: z.string(),
      guid: z
        .string()
        .regex(/^[0-9a-f]{32}$/u)
        .nullable(),
      type: z.number().int().nullable(),
    }),
  ),
  script_references: count,
  reference_types: count,
  names: z.strictObject({
    read: count.describe("Objects whose fields REA+ read."),
    unread: count.describe(
      "Objects of classes without a type tree or known layout.",
    ),
    failed: count.describe("Objects whose fields could not be decoded."),
  }),
  error: z
    .string()
    .nullable()
    .describe("Why the file's metadata could not be read, if it could not."),
});

export const unityAssetsSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    format: z.enum(["unityfs", "serialized_file"]),
  }),
  bundle: z
    .strictObject({
      format_version: count,
      unity_version: z.string(),
      unity_revision: z.string(),
      flags: z.string().regex(/^0x[0-9a-f]{1,8}$/u),
      blocks_info: z.strictObject({
        compression,
        at_end: z.boolean(),
        compressed_bytes: count,
        bytes: count,
      }),
      blocks: z.strictObject({
        count,
        compressed_bytes: count,
        bytes: count,
        compression: z.array(z.strictObject({ method: compression, count })),
      }),
      nodes: z.array(
        z.strictObject({
          path: z.string(),
          offset: count,
          size: count,
          flags: z.string().regex(/^0x[0-9a-f]{1,8}$/u),
          kind: z.enum(["serialized_file", "resource", "other"]),
        }),
      ),
      decoded_bytes: count.describe(
        "Block bytes decompressed for this report.",
      ),
    })
    .nullable(),
  serialized_files: z.array(unitySerializedFileSchema),
  classes: z
    .array(
      z.strictObject({
        class_id: z.number().int(),
        class_name: z.string().nullable(),
        objects: count,
      }),
    )
    .describe("Object counts per class across all serialized files."),
  dependencies: z
    .array(z.string())
    .describe("AssetBundle m_Dependencies: bundles this one needs loaded."),
  page: z.strictObject({
    view: z.enum(UNITY_ASSET_VIEWS),
    class_name: z.string().nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count.describe("Entries matching the filters."),
    returned: count,
  }),
  objects: z.array(unityObjectSchema),
  container: z.array(unityContainerEntrySchema),
  scripts: z.array(unityScriptSchema),
  limitations: z.array(z.string()),
});

export type InspectUnityAssetsInput = z.output<
  typeof inspectUnityAssetsInputSchema
>;
export type UnityAssets = z.output<typeof unityAssetsSchema>;
export type UnityObject = z.output<typeof unityObjectSchema>;
export type UnityContainerEntry = z.output<typeof unityContainerEntrySchema>;
export type UnityScript = z.output<typeof unityScriptSchema>;
export type UnitySerializedFile = z.output<typeof unitySerializedFileSchema>;
