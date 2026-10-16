import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const text = z.string().nullable();

export const BLOB_LAYERS = [
  "base64",
  "hex",
  "gzip",
  "zlib",
  "deflate",
  "zstd",
  "lz4",
  "brotli",
] as const;
export const BLOB_DECODERS = [
  "json",
  "nbt",
  "nbt-le",
  "bson",
  "msgpack",
  "cbor",
  "protobuf",
] as const;
export const BLOB_VIEWS = ["tree", "strings"] as const;
export const BLOB_PAGE_LIMIT = 1000;

export const inspectDataBlobInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute file: a save, cache, packet payload, settings blob or Minecraft region",
    ),
  range_offset: count
    .optional()
    .describe("Byte offset of the blob inside the file. Defaults to 0."),
  range_length: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      "Bytes to take from range_offset. Defaults to the rest of the file.",
    ),
  layers: z
    .array(z.enum(BLOB_LAYERS))
    .max(8)
    .optional()
    .describe(
      "Layers to remove in order (deflate and brotli have no signature, so name them). Without it, base64, hex, gzip, zlib, zstd and LZ4 frames are detected.",
    ),
  format: z
    .enum(["auto", ...BLOB_DECODERS, "mca"])
    .default("auto")
    .describe(
      "auto tries every format and keeps the most plausible full decoding; or json, nbt (Java), nbt-le (Bedrock), bson, msgpack, cbor, protobuf (schema-less, as protoc --decode_raw), mca (Minecraft region).",
    ),
  region_chunk: z
    .number()
    .int()
    .min(0)
    .max(1023)
    .optional()
    .describe("Chunk index (z*32+x) of a region file to decode as NBT"),
  view: z
    .enum(BLOB_VIEWS)
    .default("tree")
    .describe(
      "tree: every node with its path, type, value and byte range; strings: text leaves (or printable runs of an undecoded payload).",
    ),
  node: z
    .string()
    .min(1)
    .max(1024)
    .optional()
    .describe(
      "Path of a subtree to list, such as $.data.PlayerScores[0] or $.9[1]",
    ),
  max_depth: z
    .number()
    .int()
    .min(0)
    .max(64)
    .optional()
    .describe("Levels below the listed node to include"),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Case-insensitive substring of paths, keys, types or values"),
  offset: count.default(0).describe("Matching rows to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(BLOB_PAGE_LIMIT)
    .default(200)
    .describe("Matching rows to return"),
});

export const blobRowSchema = z.strictObject({
  path: z.string(),
  depth: count,
  key: z.union([z.string(), z.number()]).nullable(),
  type: z.string(),
  value: text,
  alternatives: z
    .record(z.string(), z.string())
    .describe(
      "Other readings: a varint as int64 or zigzag, fixed32 as float...",
    ),
  offset: count.describe("Byte offset in the payload (after layers)."),
  length: count,
  children: count,
});

export const blobStringSchema = z.strictObject({
  path: z.string(),
  offset: count,
  value: z.string(),
});

export const dataBlobSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
  }),
  range: z.strictObject({ offset: count, length: count }),
  layers: z.array(
    z.strictObject({
      kind: z.enum(BLOB_LAYERS),
      input_bytes: count,
      output_bytes: count,
    }),
  ),
  payload: z.strictObject({ bytes: count, sha256: digest }),
  format: z.strictObject({
    name: z.enum([...BLOB_DECODERS, "mca", "raw"]),
    forced: z.boolean(),
    region_chunk: count.nullable(),
  }),
  candidates: z
    .array(
      z.strictObject({
        format: z.enum(BLOB_DECODERS),
        ok: z.boolean(),
        score: z.number().int(),
        nodes: count,
        error: text,
      }),
    )
    .describe(
      "Every format tried, best first; ok means it decoded the whole payload.",
    ),
  summary: z.strictObject({
    nodes: count,
    depth: count,
    strings: count,
  }),
  page: z.strictObject({
    view: z.enum(BLOB_VIEWS),
    node: text,
    max_depth: count.nullable(),
    query: text,
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  tree: z.array(blobRowSchema),
  strings: z.array(blobStringSchema),
  limitations: z.array(z.string()),
});

export type InspectDataBlobInput = z.output<typeof inspectDataBlobInputSchema>;
export type DataBlobReport = z.output<typeof dataBlobSchema>;
