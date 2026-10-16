import { decodeLz4Block } from "../unity/Lz4Block.js";

/**
 * x64dbg program databases (db/<module>.dd32 / .dd64): the JSON document
 * DbSave writes, optionally compressed by x64dbg's lz4file as an LZ4 legacy
 * frame (magic 0x184C2102, then blocks of at most 8 MiB, each prefixed by
 * its compressed size). Addresses are "0x%llX" strings, relative to the
 * named module's base.
 */

export class X64dbgDatabaseError extends Error {
  override readonly name = "X64dbgDatabaseError";
}

const LEGACY_MAGIC = 0x184c2102;
const BLOCK_CAPACITY = 8 << 20;
const MAX_JSON_BYTES = 512 * 1024 * 1024;

/** Undo x64dbg's LZ4 compression; plain JSON passes through. */
export const inflateDatabase = (
  bytes: Buffer,
): { readonly json: Buffer; readonly compressed: boolean } => {
  if (bytes.length < 4 || bytes.readUInt32LE(0) !== LEGACY_MAGIC)
    return { json: bytes, compressed: false };
  const blocks: Buffer[] = [];
  let total = 0;
  let at = 4;
  while (at < bytes.length) {
    if (at + 4 > bytes.length)
      throw new X64dbgDatabaseError("LZ4 block size is truncated.");
    const size = bytes.readUInt32LE(at);
    // lz4 appends further frames after a magic number; x64dbg writes one.
    if (size === LEGACY_MAGIC) {
      at += 4;
      continue;
    }
    at += 4;
    if (at + size > bytes.length)
      throw new X64dbgDatabaseError("LZ4 block runs past the file.");
    const block = decodeLz4Block(
      bytes.subarray(at, at + size),
      BLOCK_CAPACITY,
      false,
    );
    total += block.length;
    if (total > MAX_JSON_BYTES)
      throw new X64dbgDatabaseError("Decompressed database is too large.");
    blocks.push(block);
    at += size;
  }
  return { json: Buffer.concat(blocks, total), compressed: true };
};

export type JsonObject = Readonly<Record<string, unknown>>;

export const objectOf = (value: unknown): JsonObject | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : null;

export const objectsOf = (value: unknown): JsonObject[] =>
  Array.isArray(value)
    ? value.flatMap((item) => {
        const object = objectOf(item);
        return object === null ? [] : [object];
      })
    : [];

export const textOf = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/** json_hex values: "0x…" strings (or plain numbers), as an unsigned bigint. */
export const hexOf = (value: unknown): bigint | null => {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
    return BigInt(value);
  if (typeof value !== "string") return null;
  const match = /^0x([0-9a-f]{1,16})$/iu.exec(value.trim());
  return match === null ? null : BigInt(`0x${match[1] ?? "0"}`);
};

export const formatHex = (value: bigint): string =>
  `0x${value.toString(16).toUpperCase()}`;

/** Parse the database JSON; x64dbg writes UTF-8 with one-space indentation. */
export const parseDatabase = (json: Buffer): JsonObject => {
  let root: unknown;
  try {
    root = JSON.parse(json.toString("utf8").replace(/^﻿/u, ""));
  } catch (cause) {
    throw new X64dbgDatabaseError("The database is not JSON.", { cause });
  }
  const object = objectOf(root);
  if (object === null)
    throw new X64dbgDatabaseError("The database is not a JSON object.");
  return object;
};

/** Current entries plus the legacy "auto…" lists (always analysis-made). */
export const listOf = (
  root: JsonObject,
  key: string,
): { item: JsonObject; auto: boolean }[] => [
  ...objectsOf(root[key]).map((item) => ({ item, auto: false })),
  ...objectsOf(root[`auto${key}`]).map((item) => ({ item, auto: true })),
];
