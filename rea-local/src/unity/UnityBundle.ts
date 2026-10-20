import { decodeLz4Block } from "./Lz4Block.js";
import { decodeLzma } from "./LzmaDecoder.js";
import {
  ByteCursor,
  formatFail,
  unityVersionParts,
  versionAtLeast,
} from "./UnityBinary.js";

/** Random access to a file or to a bundle's decompressed data stream. */
export interface ByteSource {
  readonly size: number;
  read(offset: number, length: number): Buffer;
}

export class BufferSource implements ByteSource {
  constructor(private readonly bytes: Buffer) {}

  get size(): number {
    return this.bytes.length;
  }

  read(offset: number, length: number): Buffer {
    if (offset < 0 || length < 0 || offset + length > this.bytes.length)
      formatFail("Read runs past the end of the file.");
    return this.bytes.subarray(offset, offset + length);
  }
}

export const COMPRESSION_METHODS = [
  "none",
  "lzma",
  "lz4",
  "lz4hc",
  "lzham",
] as const;
export type CompressionMethod =
  | (typeof COMPRESSION_METHODS)[number]
  | "unknown";

const compressionOf = (flags: number): CompressionMethod =>
  COMPRESSION_METHODS[flags & 0x3f] ?? "unknown";

export interface BundleBlock {
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly flags: number;
  readonly compression: CompressionMethod;
  /** Where the block's bytes start in the bundle file. */
  readonly fileOffset: number;
  /** Where the block's decoded bytes start in the data stream. */
  readonly streamOffset: number;
}

export interface BundleNode {
  readonly offset: number;
  readonly size: number;
  readonly flags: number;
  readonly path: string;
}

export interface UnityBundle {
  readonly signature: string;
  readonly formatVersion: number;
  readonly unityVersion: string;
  readonly unityRevision: string;
  readonly declaredSize: number;
  readonly flags: number;
  readonly blocksInfo: {
    readonly compression: CompressionMethod;
    readonly atEnd: boolean;
    readonly compressedSize: number;
    readonly size: number;
  };
  readonly blocks: readonly BundleBlock[];
  readonly nodes: readonly BundleNode[];
  readonly streamSize: number;
}

/** Decoded blocks larger than this are refused rather than allocated. */
export const MAX_BLOCK_BYTES = 1024 * 1024 * 1024;
const MAX_BLOCKS = 1_000_000;
const MAX_NODES = 100_000;
const BLOCK_CACHE_BYTES = 256 * 1024 * 1024;

const decode = (
  compression: CompressionMethod,
  input: Buffer,
  size: number,
): Buffer => {
  switch (compression) {
    case "none":
      if (input.length !== size)
        formatFail("Uncompressed block sizes disagree.");
      return input;
    case "lz4":
    case "lz4hc":
      return decodeLz4Block(input, size);
    case "lzma":
      return decodeLzma(input, size);
    default:
      return formatFail(`${compression} compression is not supported.`);
  }
};

/**
 * UnityCN reused 0x200 for encryption before Unity's alignment fix took the
 * bit; versions after the fix mark encryption with 0x1400 instead.
 */
const usesNewFlags = (revision: string): boolean => {
  const version = unityVersionParts(revision);
  const [major] = version;
  if (major < 2020) return false;
  if (major === 2020) return versionAtLeast(version, [2020, 3, 34]);
  if (major === 2021) return versionAtLeast(version, [2021, 3, 2]);
  if (major === 2022) return versionAtLeast(version, [2022, 1, 1]);
  return true;
};

const readBlocksInfo = (
  info: Buffer,
  formatVersion: number,
): {
  blocks: Omit<BundleBlock, "fileOffset" | "streamOffset">[];
  nodes: BundleNode[];
} => {
  const cursor = new ByteCursor(info);
  cursor.skip(16, "uncompressed data hash");
  const blockCount = cursor.count(MAX_BLOCKS, "block count");
  const blocks = Array.from({ length: blockCount }, () => {
    const uncompressedSize = cursor.u32("block size");
    const compressedSize = cursor.u32("block compressed size");
    const flags = cursor.u16("block flags");
    if (formatVersion >= 9) cursor.u64("block offset");
    if (uncompressedSize > MAX_BLOCK_BYTES)
      formatFail(`A block decodes to ${String(uncompressedSize)} bytes.`);
    return {
      uncompressedSize,
      compressedSize,
      flags,
      compression: compressionOf(flags),
    };
  });
  const nodeCount = cursor.count(MAX_NODES, "directory entry count");
  const nodes = Array.from({ length: nodeCount }, () => ({
    offset: cursor.offset("node offset"),
    size: cursor.offset("node size"),
    flags: cursor.u32("node flags"),
    path: cursor.cString("node path", 4096),
  }));
  return { blocks, nodes };
};

/** The fixed UnityFS header, leaving the cursor at the aligned blocks info. */
const readBundleHeader = (cursor: ByteCursor) => {
  const signature = cursor.cString("signature", 32);
  if (signature !== "UnityFS")
    formatFail(
      signature === "UnityWeb" || signature === "UnityRaw"
        ? `${signature} bundles (Unity 5.2 and earlier) are not supported.`
        : "Missing the UnityFS signature.",
    );
  const formatVersion = cursor.u32("bundle format version");
  if (formatVersion < 6 || formatVersion > 9)
    formatFail(
      `UnityFS format version ${String(formatVersion)} is not supported.`,
    );
  const unityVersion = cursor.cString("player version", 64);
  const unityRevision = cursor.cString("engine revision", 64);
  const header = {
    signature,
    formatVersion,
    unityVersion,
    unityRevision,
    declaredSize: cursor.offset("bundle size"),
    compressedSize: cursor.u32("blocks info compressed size"),
    size: cursor.u32("blocks info size"),
    flags: cursor.u32("bundle flags"),
    newFlags: usesNewFlags(unityRevision),
  };
  if ((header.flags & (header.newFlags ? 0x1400 : 0x200)) !== 0)
    formatFail("Encrypted (UnityCN) bundles are not supported.");
  const revision = unityVersionParts(unityRevision);
  if (
    formatVersion >= 7 ||
    (revision[0] === 2019 && versionAtLeast(revision, [2019, 4, 15]))
  )
    cursor.align(16);
  return header;
};

/** Parse a UnityFS header, block table and directory without decoding data. */
export const readUnityBundle = (file: Buffer): UnityBundle => {
  const cursor = new ByteCursor(file);
  const header = readBundleHeader(cursor);
  const { formatVersion, compressedSize, size, flags, newFlags } = header;
  const atEnd = (flags & 0x80) !== 0;
  const infoOffset = atEnd ? file.length - compressedSize : cursor.position;
  if (infoOffset < cursor.position || infoOffset + compressedSize > file.length)
    formatFail("The blocks info lies outside the file.");
  const blocksCompression = compressionOf(flags);
  const info = decode(
    blocksCompression,
    file.subarray(infoOffset, infoOffset + compressedSize),
    size,
  );
  const parsed = readBlocksInfo(info, formatVersion);
  let dataOffset = atEnd ? cursor.position : infoOffset + compressedSize;
  if (newFlags && (flags & 0x200) !== 0)
    dataOffset += (16 - (dataOffset % 16)) % 16;
  let fileOffset = dataOffset;
  let streamOffset = 0;
  const blocks = parsed.blocks.map((block) => {
    const placed = { ...block, fileOffset, streamOffset };
    fileOffset += block.compressedSize;
    streamOffset += block.uncompressedSize;
    return placed;
  });
  if (fileOffset > (atEnd ? infoOffset : file.length))
    formatFail("Compressed blocks run past the end of the file.");
  for (const node of parsed.nodes)
    if (node.offset + node.size > streamOffset)
      formatFail(`Directory entry ${node.path} lies outside the bundle data.`);
  return {
    signature: header.signature,
    formatVersion,
    unityVersion: header.unityVersion,
    unityRevision: header.unityRevision,
    declaredSize: header.declaredSize,
    flags,
    blocksInfo: { compression: blocksCompression, atEnd, compressedSize, size },
    blocks,
    nodes: parsed.nodes,
    streamSize: streamOffset,
  };
};

/** The bundle's data stream, decoding blocks on demand with a bounded cache. */
export class BundleStream implements ByteSource {
  private readonly cache = new Map<number, Buffer>();
  private cached = 0;
  decodedBytes = 0;

  constructor(
    private readonly file: Buffer,
    private readonly bundle: UnityBundle,
  ) {}

  get size(): number {
    return this.bundle.streamSize;
  }

  private blockAt(offset: number): number {
    const { blocks } = this.bundle;
    let low = 0;
    let high = blocks.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if ((blocks[middle]?.streamOffset ?? 0) <= offset) low = middle;
      else high = middle - 1;
    }
    return low;
  }

  private block(index: number): Buffer {
    const hit = this.cache.get(index);
    if (hit !== undefined) {
      this.cache.delete(index);
      this.cache.set(index, hit);
      return hit;
    }
    const block = this.bundle.blocks[index];
    if (block === undefined) return formatFail("Block index out of range.");
    const decoded = decode(
      block.compression,
      this.file.subarray(
        block.fileOffset,
        block.fileOffset + block.compressedSize,
      ),
      block.uncompressedSize,
    );
    this.decodedBytes += decoded.length;
    this.cache.set(index, decoded);
    this.cached += decoded.length;
    for (const [key, value] of this.cache) {
      if (this.cached <= BLOCK_CACHE_BYTES || key === index) break;
      this.cache.delete(key);
      this.cached -= value.length;
    }
    return decoded;
  }

  read(offset: number, length: number): Buffer {
    if (offset < 0 || length < 0 || offset + length > this.size)
      formatFail("Read runs past the end of the bundle data.");
    const parts: Buffer[] = [];
    let at = offset;
    let index = this.blockAt(offset);
    while (at < offset + length || parts.length === 0) {
      const block = this.bundle.blocks[index];
      if (block === undefined) break;
      const decoded = this.block(index);
      const start = at - block.streamOffset;
      const take = Math.min(decoded.length - start, offset + length - at);
      parts.push(decoded.subarray(start, start + take));
      at += take;
      index += 1;
      if (length === 0) break;
    }
    return parts.length === 1
      ? (parts[0] ?? Buffer.alloc(0))
      : Buffer.concat(parts);
  }
}
