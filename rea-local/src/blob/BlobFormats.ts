import { decodeBson } from "./Bson.js";
import { decodeCbor } from "./Cbor.js";
import { BlobFormatError, measure, node, type BlobNode } from "./BlobTree.js";
import { isText } from "./BlobLayers.js";
import { decodeMsgpack } from "./Msgpack.js";
import { decodeNbt } from "./Nbt.js";
import { decodeProtobuf } from "./Protobuf.js";

/**
 * The structured formats a payload may be in, each tried in full. Auto
 * detection keeps every format that decodes the whole payload and ranks
 * them: self-describing formats with strict framing first, then the
 * permissive ones by how plausible their tree looks.
 */

export const BLOB_FORMATS = [
  "json",
  "nbt",
  "nbt-le",
  "bson",
  "msgpack",
  "cbor",
  "protobuf",
] as const;
export type BlobFormat = (typeof BLOB_FORMATS)[number];

export interface Candidate {
  readonly format: BlobFormat;
  readonly ok: boolean;
  readonly score: number;
  readonly nodes: number;
  readonly error: string | null;
}

/** JSON values as a tree; JSON.parse keeps no byte offsets, so every node spans the whole text. */
const jsonTree = (
  value: unknown,
  key: BlobNode["key"],
  length: number,
): BlobNode => {
  const at = { offset: 0, length };
  if (Array.isArray(value))
    return node({
      key,
      type: "array",
      ...at,
      children: value.map((item, index) => jsonTree(item, index, length)),
    });
  if (value !== null && typeof value === "object")
    return node({
      key,
      type: "object",
      ...at,
      children: Object.entries(value).map(([name, item]) =>
        jsonTree(item, name, length),
      ),
    });
  if (typeof value === "string")
    return node({ key, type: "string", value, ...at });
  if (typeof value === "number")
    return node({ key, type: "number", value: String(value), ...at });
  if (typeof value === "boolean")
    return node({ key, type: "bool", value: String(value), ...at });
  return node({ key, type: "null", value: "null", ...at });
};

const decodeJson = (bytes: Buffer): BlobNode => {
  if (!isText(bytes) && bytes.toString("utf8").includes("�"))
    throw new BlobFormatError("Not JSON text.");
  try {
    return jsonTree(JSON.parse(bytes.toString("utf8")), null, bytes.length);
  } catch (cause) {
    throw new BlobFormatError(
      `Not JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
};

/** Bedrock's level.dat puts an 8-byte header (version, length) before little-endian NBT. */
const decodeBedrock = (bytes: Buffer): BlobNode => {
  if (
    bytes.length > 8 &&
    bytes[8] === 10 &&
    bytes.readUInt32LE(4) === bytes.length - 8
  )
    return decodeNbt(bytes.subarray(8), true);
  return decodeNbt(bytes, true);
};

export const DECODERS: Readonly<
  Record<BlobFormat, (bytes: Buffer) => BlobNode>
> = {
  json: decodeJson,
  nbt: (bytes) => decodeNbt(bytes, false),
  "nbt-le": decodeBedrock,
  bson: decodeBson,
  msgpack: decodeMsgpack,
  cbor: decodeCbor,
  protobuf: decodeProtobuf,
};

const BASE: Readonly<Record<BlobFormat, number>> = {
  json: 100,
  nbt: 95,
  "nbt-le": 94,
  bson: 90,
  msgpack: 60,
  cbor: 58,
  protobuf: 56,
};
const CONTAINERS = new Set([
  "map",
  "array",
  "message",
  "group",
  "object",
  "compound",
  "document",
]);

/** How believable a permissive decoding is: containers at the root, readable text, few opaque bytes. */
const plausibility = (format: BlobFormat, root: BlobNode): number => {
  if (BASE[format] >= 90) return BASE[format];
  const leaves: BlobNode[] = [];
  const visit = (current: BlobNode) => {
    if (current.children.length === 0) leaves.push(current);
    for (const child of current.children) visit(child);
  };
  visit(root);
  const text = leaves.filter(({ type }) => type === "string").length;
  const opaque = leaves.filter(
    ({ type }) =>
      type === "bytes" ||
      type === "str-bytes" ||
      type.startsWith("ext") ||
      type === "group",
  ).length;
  const total = Math.max(1, leaves.length);
  const rootBonus =
    CONTAINERS.has(root.type) && root.children.length > 0 ? 10 : -30;
  const oddFields =
    format === "protobuf"
      ? root.children.filter(
          (child) => typeof child.key === "number" && child.key > 100_000,
        ).length
      : 0;
  return Math.round(
    BASE[format] +
      rootBonus +
      (20 * text) / total -
      (20 * opaque) / total -
      10 * Math.min(oddFields, 3),
  );
};

/** Try every format (or only the forced one) and rank the full decodings. */
export const decodePayload = (
  bytes: Buffer,
  forced: BlobFormat | undefined,
): {
  readonly root: BlobNode | null;
  readonly format: BlobFormat | null;
  readonly candidates: Candidate[];
} => {
  const formats = forced === undefined ? BLOB_FORMATS : [forced];
  const decoded = formats.map((format) => {
    try {
      const root = DECODERS[format](bytes);
      return {
        format,
        root,
        candidate: {
          format,
          ok: true,
          score: plausibility(format, root),
          nodes: measure(root).nodes,
          error: null,
        },
      };
    } catch (cause) {
      if (!(cause instanceof BlobFormatError || cause instanceof RangeError))
        throw cause;
      return {
        format,
        root: null,
        candidate: {
          format,
          ok: false,
          score: 0,
          nodes: 0,
          error: cause.message,
        },
      };
    }
  });
  const ranked = [...decoded].sort(
    (left, right) => right.candidate.score - left.candidate.score,
  );
  const best = ranked.find(({ root }) => root !== null);
  return {
    root: best?.root ?? null,
    format: best?.format ?? null,
    candidates: ranked.map(({ candidate }) => candidate),
  };
};
