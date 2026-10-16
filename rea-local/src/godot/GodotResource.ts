import { GodotFormatError, Reader, uidText } from "./GodotBytes.js";
import { decompressGodot } from "./GodotContainers.js";
import type { GodotValue } from "./GodotValues.js";
import {
  resourceVariant,
  tableString,
  type ResourceContext,
} from "./ResourceVariant.js";

/**
 * Binary resources (.res, .scn and the binary forms of .tres/.tscn that
 * exports produce), as resource_format_binary.cpp writes them in Godot 3
 * and 4: a header, a string table, external and internal resource lists,
 * then each internal resource's type and properties.
 */

const FLAGS: readonly (readonly [number, string])[] = [
  [1, "named_scene_ids"],
  [2, "uids"],
  [4, "real_t_is_double"],
  [8, "has_script_class"],
];

export interface ResourceHeader {
  readonly compressed: string | null;
  readonly bigEndian: boolean;
  readonly real64: boolean;
  readonly major: number;
  readonly minor: number;
  readonly format: number;
  readonly type: string;
  readonly flags: readonly string[];
  readonly uid: string | null;
  readonly scriptClass: string | null;
}

export interface ResourceEntry {
  /** The id SubResource() uses, or "main" for the file's own resource. */
  readonly id: string;
  readonly type: string;
  readonly offset: number;
  /** Where its properties end, or null when they could not be read. */
  readonly end: number | null;
  readonly properties: readonly {
    readonly name: string;
    readonly value: GodotValue;
  }[];
  readonly error: string | null;
}

export interface GodotResourceFile {
  readonly header: ResourceHeader;
  readonly strings: readonly string[];
  readonly external: readonly {
    readonly type: string;
    readonly path: string;
    readonly uid: string | null;
  }[];
  readonly resources: readonly ResourceEntry[];
  /** Godot ends every binary resource with RSRC again. */
  readonly trailer: boolean;
}

export const isGodotResource = (bytes: Buffer): boolean =>
  bytes.length >= 4 &&
  ["RSRC", "RSCC"].includes(bytes.subarray(0, 4).toString("latin1"));

const count = (reader: Reader, size: number, what: string): number => {
  const value = reader.u32();
  if (value * size > reader.bytes.length - reader.at)
    throw new GodotFormatError(
      `${String(value)} ${what} cannot fit in the file.`,
    );
  return value;
};

const header = (reader: Reader, compressed: string | null): ResourceHeader => {
  const bigEndian = reader.u32() !== 0;
  reader.big = bigEndian;
  const real64 = reader.u32() !== 0;
  const major = reader.u32();
  const minor = reader.u32();
  const format = reader.u32();
  if (major < 1 || major > 9 || format > 64)
    throw new GodotFormatError(
      `Engine ${String(major)}.${String(minor)}, format ${String(format)} is not a Godot binary resource.`,
    );
  const type = reader.text();
  reader.u64(); // offset of import metadata, used by the editor only
  // Godot 3 left these 14 words reserved; Godot 4 puts flags, a UID and
  // an optional script class in the first ones, so one layout reads both.
  const bits = reader.u32();
  const uid = reader.u64();
  const scriptClass = (bits & 8) === 0 ? null : reader.text();
  reader.need(11 * 4, "reserved fields");
  return {
    compressed,
    bigEndian,
    real64: real64 || (bits & 4) !== 0,
    major,
    minor,
    format,
    type,
    flags: FLAGS.filter(([bit]) => (bits & bit) !== 0).map(([, name]) => name),
    uid: (bits & 2) === 0 ? null : uidText(uid),
    scriptClass,
  };
};

/** The last internal resource is the file's own; Godot 3 also stores it as local://N. */
const resourceId = (path: string, last: boolean): string => {
  if (last) return "main";
  return path.startsWith("local://") ? path.slice("local://".length) : path;
};

/** Read a binary resource, decompressing RSCC files first. */
export const readGodotResource = (
  bytes: Buffer,
  maxOutput: number,
): GodotResourceFile => {
  const compressed = bytes.subarray(0, 4).toString("latin1") === "RSCC";
  const unpacked = compressed ? decompressGodot(bytes, maxOutput) : null;
  const stream = unpacked?.data ?? bytes;
  const reader = new Reader(stream, compressed ? 0 : 4);
  const head = header(reader, unpacked?.mode ?? null);
  const strings = Array.from({ length: count(reader, 4, "strings") }, () =>
    reader.text(),
  );
  const uids = head.flags.includes("uids");
  const external = Array.from(
    { length: count(reader, 8, "external resources") },
    () => {
      const type = reader.text();
      const path = reader.text();
      return { type, path, uid: uids ? uidText(reader.u64()) : null };
    },
  );
  const internal = Array.from(
    { length: count(reader, 12, "internal resources") },
    () => ({
      path: reader.text(),
      offset: Number(reader.u64()),
    }),
  );
  const named = head.flags.includes("named_scene_ids");
  const context: ResourceContext = {
    reader,
    major: head.major,
    format: head.format,
    real64: head.real64,
    strings,
    external,
    internalIds: named
      ? internal.map(({ path }, index) =>
          resourceId(path, index === internal.length - 1),
        )
      : null,
  };
  const resources = internal.map(({ path, offset }, index): ResourceEntry => {
    const id = resourceId(path, index === internal.length - 1);
    const properties: { name: string; value: GodotValue }[] = [];
    let type = "";
    try {
      reader.at = offset;
      type = reader.text();
      const total = count(reader, 8, "properties");
      for (let property = 0; property < total; property += 1)
        properties.push({
          name: tableString(context),
          value: resourceVariant(context),
        });
      return { id, type, offset, end: reader.at, properties, error: null };
    } catch (cause) {
      if (!(cause instanceof GodotFormatError)) throw cause;
      return {
        id,
        type,
        offset,
        end: null,
        properties,
        error: cause.message,
      };
    }
  });
  return {
    header: head,
    strings,
    external,
    resources,
    trailer: stream.subarray(-4).toString("latin1") === "RSRC",
  };
};
