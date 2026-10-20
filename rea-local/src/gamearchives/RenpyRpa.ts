import { inflateSync } from "node:zlib";

import {
  archiveFail,
  type ArchiveEntry,
  type ArchiveListing,
  type EntryPart,
} from "./GameArchiveTypes.js";
import { decodeSafePickle, type PickleValue } from "./SafePickle.js";

const MAX_INDEX_BYTES = 256 * 1024 * 1024;

/** Ren'Py archive headers: `RPA-3.0 <index offset> <xor key>`, or no key for 2.0. */
export const isRenpyArchive = (bytes: Buffer): boolean =>
  /^RPA-(?:2\.0|3\.0|3\.2|4\.0) /u.test(bytes.toString("latin1", 0, 8));

const integer = (value: PickleValue | undefined): bigint =>
  typeof value === "bigint"
    ? value
    : archiveFail("An index field is not an integer.");

const prefixBytes = (value: PickleValue | undefined): Buffer | null => {
  if (value === undefined || value === null) return null;
  if (Buffer.isBuffer(value)) return value.length === 0 ? null : value;
  if (typeof value === "string")
    return value.length === 0 ? null : Buffer.from(value, "latin1");
  return archiveFail("An index prefix is neither bytes nor text.");
};

const entryOf = (
  name: string,
  tuples: PickleValue,
  key: bigint,
  fileSize: number,
): ArchiveEntry => {
  if (!Array.isArray(tuples)) archiveFail(`Index entry ${name} is not a list.`);
  const parts: EntryPart[] = [];
  for (const tuple of tuples as readonly PickleValue[]) {
    if (!Array.isArray(tuple) || tuple.length < 2)
      archiveFail(`Index entry ${name} has a malformed part.`);
    const fields = tuple as readonly PickleValue[];
    const prefix = prefixBytes(fields[2]);
    if (prefix !== null) parts.push({ kind: "inline", bytes: prefix });
    const offset = integer(fields[0]) ^ key;
    const length = integer(fields[1]) ^ key;
    if (offset < 0n || length < 0n || offset + length > BigInt(fileSize))
      archiveFail(`Index entry ${name} points outside the archive.`);
    parts.push({
      kind: "file",
      offset: Number(offset),
      length: Number(length),
    });
  }
  return {
    path: name,
    size: parts.reduce(
      (sum, part) =>
        sum + (part.kind === "inline" ? part.bytes.length : part.length),
      0,
    ),
    parts,
    encrypted: false,
    removed: false,
    group: null,
    checksum: null,
  };
};

/** Parse a Ren'Py RPA archive; the index pickle is decoded without running code. */
export const readRenpyArchive = (bytes: Buffer): ArchiveListing => {
  const end = bytes.indexOf(0x0a);
  const header = bytes.toString("latin1", 0, end < 0 || end > 128 ? 128 : end);
  const [tag = "", offsetText = "", keyText] = header.split(/\s+/u);
  const version = tag.slice(4);
  if (!/^[0-9a-f]+$/iu.test(offsetText))
    archiveFail("The RPA header has no index offset.");
  const offset = Number.parseInt(offsetText, 16);
  const key =
    version === "2.0"
      ? 0n
      : /^[0-9a-f]+$/iu.test(keyText ?? "")
        ? BigInt(`0x${keyText ?? "0"}`)
        : archiveFail("The RPA header has no key.");
  if (offset <= 0 || offset >= bytes.length)
    archiveFail("The RPA index offset lies outside the file.");
  let inflated: Buffer;
  try {
    inflated = inflateSync(bytes.subarray(offset), {
      maxOutputLength: MAX_INDEX_BYTES,
    });
  } catch (cause: unknown) {
    return archiveFail(
      `The RPA index does not inflate: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const index = decodeSafePickle(inflated);
  if (!(index instanceof Map)) archiveFail("The RPA index is not a dict.");
  const entries = [...(index as Map<PickleValue, PickleValue>)].map(
    ([name, tuples]) =>
      entryOf(
        Buffer.isBuffer(name) ? name.toString("utf8") : String(name),
        tuples,
        key,
        bytes.length,
      ),
  );
  return {
    format: "renpy_rpa",
    version,
    embeddedAt: null,
    engineVersion: null,
    flags: key === 0n ? [] : ["xor_obfuscated_index"],
    entries,
    notes:
      key === 0n
        ? []
        : [
            `Index offsets and lengths are XORed with key 0x${key.toString(16)}.`,
          ],
  };
};
