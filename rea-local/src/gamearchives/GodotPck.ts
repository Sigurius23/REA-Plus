import {
  archiveFail,
  range,
  type ArchiveEntry,
  type ArchiveListing,
} from "./GameArchiveTypes.js";

const MAGIC = 0x43504447; // "GDPC"
const DIR_ENCRYPTED = 1 << 0;
const REL_FILEBASE = 1 << 1;
const SPARSE_BUNDLE = 1 << 2;
const FILE_ENCRYPTED = 1 << 0;
const FILE_REMOVAL = 1 << 1;
const FILE_DELTA = 1 << 2;

const PACK_FLAGS: readonly [number, string][] = [
  [DIR_ENCRYPTED, "directory_encrypted"],
  [REL_FILEBASE, "relative_file_base"],
  [SPARSE_BUNDLE, "sparse_bundle"],
];

/**
 * Where a Godot pack starts: at offset 0 for a .pck, or before the
 * `[size u64][GDPC]` trailer Godot appends when embedding a pack in an
 * exported executable.
 */
export const locateGodotPack = (bytes: Buffer): number | null => {
  if (bytes.length >= 4 && bytes.readUInt32LE(0) === MAGIC) return 0;
  if (bytes.length < 16 || bytes.readUInt32LE(bytes.length - 4) !== MAGIC)
    return null;
  const size = bytes.readBigUInt64LE(bytes.length - 12);
  const start = BigInt(bytes.length) - 12n - size;
  if (start < 0n) return null;
  const offset = Number(start);
  return bytes.readUInt32LE(offset) === MAGIC ? offset : null;
};

const u32 = (bytes: Buffer, at: number, what: string) =>
  range(bytes, at, 4, what).readUInt32LE(0);

const u64 = (bytes: Buffer, at: number, what: string): number => {
  const value = range(bytes, at, 8, what).readBigUInt64LE(0);
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    archiveFail(`${what} is too large.`);
  return Number(value);
};

interface Directory {
  readonly at: number;
  readonly base: number;
  readonly flags: number;
}

/** Header fields that place the directory and the file data. */
const directoryOf = (
  bytes: Buffer,
  start: number,
  version: number,
): Directory => {
  if (version === 1) return { at: start + 84, base: 0, flags: 0 };
  const flags = u32(bytes, start + 20, "pack flags");
  const fileBase = u64(bytes, start + 24, "file base");
  if (version === 2)
    return {
      at: start + 96,
      base: fileBase + ((flags & REL_FILEBASE) !== 0 ? start : 0),
      flags,
    };
  return {
    at: start + u64(bytes, start + 32, "directory offset"),
    base: fileBase + start,
    flags,
  };
};

const readEntry = (
  bytes: Buffer,
  at: number,
  version: number,
  base: number,
): { entry: ArchiveEntry; next: number } => {
  const pathLength = u32(bytes, at, "path length");
  if (pathLength > 64 * 1024) archiveFail("A path length is out of range.");
  const path = range(bytes, at + 4, pathLength, "path")
    .toString("utf8")
    .replace(/\0+$/u, "")
    .replace(/^res:\/\//u, "");
  let cursor = at + 4 + pathLength;
  const offset = u64(bytes, cursor, "file offset");
  const size = u64(bytes, cursor + 8, "file size");
  const md5 = range(bytes, cursor + 16, 16, "file md5");
  cursor += 32;
  const flags = version >= 2 ? u32(bytes, cursor, "file flags") : 0;
  if (version >= 2) cursor += 4;
  const removed = (flags & FILE_REMOVAL) !== 0;
  const encrypted = (flags & FILE_ENCRYPTED) !== 0;
  return {
    entry: {
      path,
      size: removed ? 0 : size,
      parts: removed
        ? []
        : [{ kind: "file", offset: base + offset, length: size }],
      encrypted,
      removed,
      group: (flags & FILE_DELTA) !== 0 ? "delta_patch" : null,
      checksum: md5.every((byte) => byte === 0)
        ? null
        : { algorithm: "md5", value: md5.toString("hex") },
    },
    next: cursor,
  };
};

/** Parse a Godot 3.x-4.x resource pack (.pck, or one embedded in an executable). */
export const readGodotPack = (bytes: Buffer): ArchiveListing => {
  const start = locateGodotPack(bytes) ?? archiveFail("No Godot pack header.");
  const version = u32(bytes, start + 4, "pack version");
  if (version < 1 || version > 4)
    archiveFail(`Godot pack format ${String(version)} is not supported.`);
  const engine = [8, 12, 16].map((at) =>
    u32(bytes, start + at, "engine version"),
  );
  const directory = directoryOf(bytes, start, version);
  const count = u32(bytes, directory.at, "file count");
  const flags = PACK_FLAGS.filter(([bit]) => (directory.flags & bit) !== 0).map(
    ([, name]) => name,
  );
  const listing = {
    format: "godot_pck" as const,
    version: String(version),
    embeddedAt: start === 0 ? null : start,
    engineVersion: engine.join("."),
    flags,
  };
  if ((directory.flags & DIR_ENCRYPTED) !== 0)
    return {
      ...listing,
      entries: [],
      notes: [
        `The directory of ${String(count)} entries is AES-encrypted with the game's script key; REA+ lists none.`,
      ],
    };
  if (count > (bytes.length - directory.at) / 32)
    archiveFail(`File count ${String(count)} is out of range.`);
  const entries: ArchiveEntry[] = [];
  let at = directory.at + 4;
  for (let index = 0; index < count; index += 1) {
    const read = readEntry(bytes, at, version, directory.base);
    entries.push(read.entry);
    at = read.next;
  }
  return {
    ...listing,
    entries,
    notes:
      (directory.flags & SPARSE_BUNDLE) !== 0
        ? [
            "Sparse-bundle packs store file data in bundles REA+ does not decode; offsets are as recorded.",
          ]
        : [],
  };
};
