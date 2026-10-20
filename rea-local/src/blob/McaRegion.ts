import { gunzipSync, inflateSync } from "node:zlib";

import { BlobFormatError, node, type BlobNode } from "./BlobTree.js";
import { decodeLz4Frames } from "./Lz4Frame.js";

/**
 * Minecraft Anvil region files (.mca, and the older .mcr): a 4 KiB table of
 * 1024 chunk locations, a 4 KiB table of timestamps, then chunks in 4 KiB
 * sectors, each a length, a compression byte and compressed NBT.
 */

const SECTOR = 4096;
const COMPRESSION: Readonly<Record<number, string>> = {
  1: "gzip",
  2: "zlib",
  3: "none",
  4: "lz4",
};

export interface RegionChunk {
  readonly index: number;
  readonly x: number;
  readonly z: number;
  readonly sector: number;
  readonly sectors: number;
  readonly timestamp: number;
  readonly length: number;
  readonly compression: string;
  /** Why the entry cannot be read; region files in the wild carry broken entries. */
  readonly error: string | null;
}

const entry = (bytes: Buffer, index: number, location: number): RegionChunk => {
  const sector = location >>> 8;
  const sectors = location & 0xff;
  const base = {
    index,
    x: index % 32,
    z: Math.floor(index / 32),
    sector,
    sectors,
    timestamp: bytes.readUInt32BE(SECTOR + index * 4),
  };
  if (sector < 2 || sector * SECTOR + 5 > bytes.length)
    return {
      ...base,
      length: 0,
      compression: "?",
      error: `Sector ${String(sector)} is outside the file.`,
    };
  const length = bytes.readUInt32BE(sector * SECTOR);
  const type = bytes[sector * SECTOR + 4] ?? 0;
  // External chunks (.mcc files) set the high bit of the compression byte.
  const compression =
    (type & 0x80) !== 0
      ? "external"
      : (COMPRESSION[type] ?? `type ${String(type)}`);
  const error =
    sectors === 0
      ? "The location claims zero sectors."
      : length <= 1
        ? `The chunk holds no data (length ${String(length)}).`
        : sector * SECTOR + 4 + length > bytes.length
          ? `A length of ${String(length)} runs past the file.`
          : length > sectors * SECTOR
            ? `A length of ${String(length)} overflows its ${String(sectors)} sectors.`
            : COMPRESSION[type] === undefined && (type & 0x80) === 0
              ? `Unknown compression type ${String(type)}.`
              : null;
  return { ...base, length, compression, error };
};

/** Present chunks, or null when the bytes do not look like a region file. */
export const regionChunks = (bytes: Buffer): RegionChunk[] | null => {
  if (bytes.length < 2 * SECTOR) return null;
  const chunks: RegionChunk[] = [];
  for (let index = 0; index < 1024; index += 1) {
    const location = bytes.readUInt32BE(index * 4);
    if (location !== 0) chunks.push(entry(bytes, index, location));
  }
  const readable = chunks.filter(({ error }) => error === null).length;
  return readable === 0 || readable < chunks.length - readable ? null : chunks;
};

/** The chunk list as a tree for the region view. */
export const regionTree = (
  chunks: readonly RegionChunk[],
  total: number,
): BlobNode =>
  node({
    key: null,
    type: "region",
    offset: 0,
    length: total,
    children: chunks.map((chunk) =>
      node({
        key: chunk.index,
        type: "chunk",
        value:
          chunk.error === null
            ? `x=${String(chunk.x)} z=${String(chunk.z)} ${chunk.compression} ${String(chunk.length)} bytes, saved ${new Date(chunk.timestamp * 1000).toISOString()}`
            : `x=${String(chunk.x)} z=${String(chunk.z)} unreadable: ${chunk.error}`,
        offset: chunk.sector * SECTOR,
        length: chunk.length + 4,
      }),
    ),
  });

const decompress = (
  compression: string,
  data: Buffer,
  maxOutput: number,
): Buffer | null => {
  if (compression === "gzip")
    return gunzipSync(data, { maxOutputLength: maxOutput });
  if (compression === "zlib")
    return inflateSync(data, { maxOutputLength: maxOutput });
  if (compression === "lz4") return decodeLz4Frames(data, maxOutput);
  if (compression === "none") return Buffer.from(data);
  return null;
};

const cutShort = (cause: unknown): boolean =>
  cause instanceof Error && "code" in cause && cause.code === "Z_BUF_ERROR";

/** One chunk's NBT bytes, decompressed. */
export const regionChunkPayload = (
  bytes: Buffer,
  chunk: RegionChunk,
  maxOutput: number,
): Buffer => {
  if (chunk.error !== null)
    throw new BlobFormatError(`Chunk ${String(chunk.index)}: ${chunk.error}`);
  const start = chunk.sector * SECTOR + 5;
  const data = bytes.subarray(start, start + chunk.length - 1);
  // Some writers store a length a byte short, cutting off the end of the
  // stream; the rest still lies in the chunk's own sectors.
  const allocated = bytes.subarray(
    start,
    (chunk.sector + chunk.sectors) * SECTOR,
  );
  let payload: Buffer | null;
  try {
    try {
      payload = decompress(chunk.compression, data, maxOutput);
    } catch (cause) {
      if (!cutShort(cause) || allocated.length <= data.length) throw cause;
      payload = decompress(chunk.compression, allocated, maxOutput);
    }
  } catch (cause) {
    throw new BlobFormatError(
      `Chunk ${String(chunk.index)} does not decompress: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  if (payload !== null) return payload;
  throw new BlobFormatError(
    `Chunk ${String(chunk.index)} uses ${chunk.compression} storage, which is not read.`,
  );
};
