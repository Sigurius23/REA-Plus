/** A file that is not a supported game archive, or whose index is damaged. */
export class GameArchiveError extends Error {}

export const archiveFail = (message: string): never => {
  throw new GameArchiveError(message);
};

/** One run of an entry's bytes: in this file, inline in the index, or elsewhere. */
export type EntryPart =
  | { readonly kind: "file"; readonly offset: number; readonly length: number }
  | { readonly kind: "inline"; readonly bytes: Buffer }
  | {
      readonly kind: "external";
      readonly file: string;
      readonly offset: number;
      readonly length: number;
    };

export interface ArchiveEntry {
  readonly path: string;
  readonly size: number;
  readonly parts: readonly EntryPart[];
  readonly encrypted: boolean;
  readonly removed: boolean;
  /** WAD namespace or map; null for formats with real directories. */
  readonly group: string | null;
  readonly checksum: {
    readonly algorithm: "md5" | "crc32";
    readonly value: string;
  } | null;
}

export type GameArchiveFormat =
  | "godot_pck"
  | "renpy_rpa"
  | "valve_vpk"
  | "doom_wad";

export interface ArchiveListing {
  readonly format: GameArchiveFormat;
  readonly version: string;
  /** Where an embedded archive starts inside a larger file, such as a game executable. */
  readonly embeddedAt: number | null;
  readonly engineVersion: string | null;
  readonly flags: readonly string[];
  /** Entries listed by the index; empty when the index itself is encrypted. */
  readonly entries: readonly ArchiveEntry[];
  readonly notes: readonly string[];
}

/** Read a bounded range of the selected file. */
export const range = (
  bytes: Buffer,
  offset: number,
  length: number,
  what: string,
): Buffer => {
  if (offset < 0 || length < 0 || offset + length > bytes.length)
    archiveFail(`${what} lies outside the file.`);
  return bytes.subarray(offset, offset + length);
};
