import { createDecipheriv, createHash } from "node:crypto";
import {
  brotliDecompressSync,
  gunzipSync,
  inflateSync,
  zstdDecompressSync,
} from "node:zlib";

import { GodotFormatError, Reader } from "./GodotBytes.js";
import { fastLzDecompress } from "./FastLz.js";

/**
 * Godot's file wrappers: FileAccessCompressed (GCPF for open_compressed,
 * RSCC for compressed binary resources) and FileAccessEncrypted (GDEC for
 * open_encrypted and Godot 3's encrypted .gde scripts).
 */

export const COMPRESSION_MODES = [
  "fastlz",
  "deflate",
  "zstd",
  "gzip",
  "brotli",
] as const;

const decodeBlock = (mode: number, block: Buffer, size: number): Buffer => {
  const limit = { maxOutputLength: Math.max(1, size) };
  switch (mode) {
    case 0:
      return fastLzDecompress(block, size);
    case 1:
      return inflateSync(block, limit);
    case 2:
      return zstdDecompressSync(block, limit);
    case 3:
      return gunzipSync(block, limit);
    case 4:
      return brotliDecompressSync(block, limit);
    default:
      throw new GodotFormatError(
        `Compression mode ${String(mode)} is not one Godot defines.`,
      );
  }
};

/** The blocks after a GCPF or RSCC magic, decompressed. */
export const decompressGodot = (
  bytes: Buffer,
  maxOutput: number,
): { readonly data: Buffer; readonly mode: string } => {
  const reader = new Reader(bytes, 4);
  const mode = reader.u32();
  const blockSize = reader.u32();
  const total = reader.u32();
  if (blockSize === 0)
    throw new GodotFormatError("The compressed file declares 0-byte blocks.");
  if (total > maxOutput)
    throw new GodotFormatError(
      `The compressed file expands to ${String(total)} bytes, over the limit.`,
    );
  const count = Math.floor(total / blockSize) + 1;
  if (count * 4 > bytes.length)
    throw new GodotFormatError(`${String(count)} block sizes cannot fit.`);
  const sizes = Array.from({ length: count }, () => reader.u32());
  const data = Buffer.alloc(total);
  sizes.forEach((compressed, index) => {
    const size = Math.min(blockSize, total - index * blockSize);
    const block = reader.take(compressed, `block ${String(index)}`);
    const out = decodeBlock(mode, block, size);
    if (out.length !== size)
      throw new GodotFormatError(
        `Block ${String(index)} holds ${String(out.length)} bytes, not ${String(size)}.`,
      );
    out.copy(data, index * blockSize);
  });
  return { data, mode: COMPRESSION_MODES[mode] ?? `mode ${String(mode)}` };
};

/** The 32 key bytes Godot derives from a password: the ASCII of its MD5 hex. */
export const passwordKey = (password: string): Buffer =>
  Buffer.from(
    createHash("md5").update(password, "utf8").digest("hex"),
    "ascii",
  );

const md5 = (data: Buffer): Buffer => createHash("md5").update(data).digest();

const decipher = (
  algorithm: "aes-256-ecb" | "aes-256-cfb",
  key: Buffer,
  iv: Buffer | null,
  data: Buffer,
): Buffer => {
  const cipher = createDecipheriv(algorithm, key, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};

const padded = (length: bigint): number => Number((length + 15n) & ~15n);

/** Godot 3: mode, MD5, length, then AES-256 in ECB mode. */
const godot3 = (bytes: Buffer, key: Buffer): Buffer | null => {
  const reader = new Reader(bytes, 4);
  if (reader.u32() !== 1) return null;
  const sum = reader.take(16);
  const length = reader.u64();
  if (BigInt(reader.at) + length > BigInt(bytes.length)) return null;
  const data = decipher(
    "aes-256-ecb",
    key,
    null,
    reader.take(padded(length)),
  ).subarray(0, Number(length));
  return md5(data).equals(sum) ? data : null;
};

/** Godot 4: MD5, length, IV, then AES-256 in CFB mode. */
const godot4 = (bytes: Buffer, key: Buffer): Buffer | null => {
  const reader = new Reader(bytes, 4);
  const sum = reader.take(16);
  const length = reader.u64();
  const iv = reader.take(16);
  if (BigInt(reader.at) + BigInt(padded(length)) > BigInt(bytes.length))
    return null;
  const data = decipher(
    "aes-256-cfb",
    key,
    iv,
    reader.take(padded(length)),
  ).subarray(0, Number(length));
  return md5(data).equals(sum) ? data : null;
};

/**
 * A GDEC file decrypted with a 32-byte key, checked against the MD5 Godot
 * stores; null when the key does not fit.
 */
export const decryptGodot = (
  bytes: Buffer,
  key: Buffer,
): { readonly data: Buffer; readonly engine: 3 | 4 } | null => {
  for (const [engine, attempt] of [
    [4, godot4],
    [3, godot3],
  ] as const) {
    try {
      const data = attempt(bytes, key);
      if (data !== null) return { data, engine };
    } catch (cause) {
      if (!(cause instanceof GodotFormatError)) throw cause;
    }
  }
  return null;
};
