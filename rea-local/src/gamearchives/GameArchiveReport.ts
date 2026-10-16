import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";

import type {
  GameArchive,
  GameArchiveEntry,
  InspectGameArchiveInput,
} from "../domain/gamearchives/gameArchive.js";
import { isDoomWad, readDoomWad } from "./DoomWad.js";
import {
  archiveFail,
  type ArchiveEntry,
  type ArchiveListing,
} from "./GameArchiveTypes.js";
import { locateGodotPack, readGodotPack } from "./GodotPck.js";
import { isRenpyArchive, readRenpyArchive } from "./RenpyRpa.js";
import { isValveVpk, readValveVpk } from "./ValveVpk.js";

/** The selected `entry` is not in the archive. */
export class GameArchiveEntryNotFound extends Error {}

const MAX_VERIFIED_ENTRY = 64 * 1024 * 1024;
const MAX_VERIFIED_PAGE = 256 * 1024 * 1024;
const MAX_EXTENSIONS = 50;

const basename = (path: string): string =>
  path.slice(Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\")) + 1);

export const readArchiveListing = (
  bytes: Buffer,
  path: string,
): ArchiveListing => {
  if (isValveVpk(bytes)) return readValveVpk(bytes, basename(path));
  if (isRenpyArchive(bytes)) return readRenpyArchive(bytes);
  if (isDoomWad(bytes)) return readDoomWad(bytes);
  if (locateGodotPack(bytes) !== null) return readGodotPack(bytes);
  return archiveFail(
    "Not a Godot pack, Ren'Py archive, Valve VPK or Doom WAD.",
  );
};

const extensionOf = (path: string): string => {
  const name = basename(path.replace(/#\d+$/u, ""));
  const dot = name.lastIndexOf(".");
  return dot <= 0 ? "" : name.slice(dot + 1).toLowerCase();
};

/** The entry's bytes when they are all in the selected file, or why not. */
const entryBytes = (
  bytes: Buffer,
  entry: ArchiveEntry,
): { data: Buffer } | { reason: string } => {
  if (entry.removed)
    return { reason: "The entry deletes the path; it has no data." };
  if (entry.encrypted) return { reason: "The entry is encrypted." };
  const external = entry.parts.find((part) => part.kind === "external");
  if (external?.kind === "external")
    return { reason: `The data is in sibling archive ${external.file}.` };
  return {
    data: Buffer.concat(
      entry.parts.map((part) =>
        part.kind === "inline"
          ? part.bytes
          : part.kind === "file"
            ? bytes.subarray(part.offset, part.offset + part.length)
            : Buffer.alloc(0),
      ),
    ),
  };
};

const checksumMatches = (entry: ArchiveEntry, data: Buffer): boolean | null => {
  if (entry.checksum === null) return null;
  const actual =
    entry.checksum.algorithm === "md5"
      ? createHash("md5").update(data).digest("hex")
      : crc32(data).toString(16).padStart(8, "0");
  return actual === entry.checksum.value;
};

const entryRow = (
  bytes: Buffer,
  entry: ArchiveEntry,
  budget: { left: number },
): GameArchiveEntry => {
  const local = entry.parts.find((part) => part.kind === "file");
  const external = entry.parts.find((part) => part.kind === "external");
  let verified: boolean | null = null;
  if (
    entry.checksum !== null &&
    entry.size <= MAX_VERIFIED_ENTRY &&
    entry.size <= budget.left
  ) {
    const read = entryBytes(bytes, entry);
    if ("data" in read) {
      budget.left -= entry.size;
      verified = checksumMatches(entry, read.data);
    }
  }
  return {
    path: entry.path,
    size: entry.size,
    offset: local?.kind === "file" ? local.offset : null,
    stored_in: external?.kind === "external" ? external.file : null,
    inline_bytes: entry.parts.reduce(
      (sum, part) => sum + (part.kind === "inline" ? part.bytes.length : 0),
      0,
    ),
    encrypted: entry.encrypted,
    removed: entry.removed,
    group: entry.group,
    checksum: entry.checksum === null ? null : { ...entry.checksum, verified },
  };
};

/** Entries with a NUL in their first 8 KiB are binary, as git decides. */
const BINARY_PROBE = 8192;

/** UTF-8 text when the entry is text and the preview decodes, otherwise hex. */
const previewOf = (
  data: Buffer,
  limit: number,
): { encoding: "utf8" | "hex"; preview: string } => {
  const shown = data.subarray(0, limit);
  if (!data.subarray(0, BINARY_PROBE).includes(0))
    for (let trim = 0; trim < 4 && trim <= shown.length; trim += 1)
      try {
        return {
          encoding: "utf8",
          preview: new TextDecoder("utf-8", { fatal: true }).decode(
            shown.subarray(0, shown.length - trim),
          ),
        };
      } catch {
        // A multi-byte character may be cut at the preview boundary.
      }
  return { encoding: "hex", preview: shown.toString("hex") };
};

const selectedEntry = (
  bytes: Buffer,
  entries: readonly ArchiveEntry[],
  input: InspectGameArchiveInput,
): GameArchive["entry"] => {
  if (input.entry === undefined) return null;
  const wanted = input.entry.replace(/^res:\/\//u, "");
  const entry =
    entries.find((candidate) => candidate.path === wanted) ??
    (() => {
      throw new GameArchiveEntryNotFound(
        `No entry named ${input.entry ?? ""}; use the listing's exact path.`,
      );
    })();
  const read = entryBytes(bytes, entry);
  if (!("data" in read))
    return {
      path: entry.path,
      size: entry.size,
      available: false,
      reason: read.reason,
      sha256: null,
      checksum_verified: null,
      encoding: null,
      preview: null,
      truncated: false,
    };
  const shown = previewOf(read.data, input.preview_bytes);
  return {
    path: entry.path,
    size: entry.size,
    available: true,
    reason: null,
    sha256: createHash("sha256").update(read.data).digest("hex"),
    checksum_verified: checksumMatches(entry, read.data),
    ...shown,
    truncated: read.data.length > input.preview_bytes,
  };
};

const extensionsOf = (entries: readonly ArchiveEntry[]) => {
  const totals = new Map<
    string,
    { extension: string; entries: number; bytes: number }
  >();
  for (const entry of entries) {
    const extension = extensionOf(entry.path);
    const total = totals.get(extension) ?? { extension, entries: 0, bytes: 0 };
    total.entries += 1;
    total.bytes += entry.size;
    totals.set(extension, total);
  }
  return [...totals.values()]
    .sort(
      (left, right) =>
        right.entries - left.entries ||
        left.extension.localeCompare(right.extension),
    )
    .slice(0, MAX_EXTENSIONS);
};

/** List, filter and page one archive, with an optional entry preview. */
export const buildGameArchiveReport = (
  bytes: Buffer,
  input: InspectGameArchiveInput,
  identity: { readonly sha256: string },
  limitations: readonly string[],
): GameArchive => {
  const listing = readArchiveListing(bytes, input.path);
  const needle = input.query?.toLowerCase();
  const extension = input.extension?.toLowerCase();
  const matching = listing.entries.filter(
    (entry) =>
      (needle === undefined || entry.path.toLowerCase().includes(needle)) &&
      (extension === undefined || extensionOf(entry.path) === extension),
  );
  const budget = { left: MAX_VERIFIED_PAGE };
  const page = matching
    .slice(input.offset, input.offset + input.limit)
    .map((entry) => entryRow(bytes, entry, budget));
  return {
    archive: {
      path: input.path,
      sha256: identity.sha256,
      bytes: bytes.length,
      format: listing.format,
      version: listing.version,
      engine_version: listing.engineVersion,
      embedded_at: listing.embeddedAt,
      flags: [...listing.flags],
      entries: listing.entries.length,
      entry_bytes: listing.entries.reduce((sum, entry) => sum + entry.size, 0),
      extensions: extensionsOf(listing.entries),
      notes: [...listing.notes],
    },
    page: {
      query: input.query ?? null,
      extension: input.extension ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    entries: page,
    entry: selectedEntry(bytes, listing.entries, input),
    limitations: [...limitations],
  };
};
