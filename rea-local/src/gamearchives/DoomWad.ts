import {
  archiveFail,
  type ArchiveEntry,
  type ArchiveListing,
} from "./GameArchiveTypes.js";

export const isDoomWad = (bytes: Buffer): boolean =>
  bytes.length >= 12 && /^[IP]WAD$/u.test(bytes.toString("latin1", 0, 4));

/** Lumps that belong to the map marker before them. */
const MAP_LUMPS = new Set([
  "THINGS",
  "LINEDEFS",
  "SIDEDEFS",
  "VERTEXES",
  "SEGS",
  "SSECTORS",
  "NODES",
  "SECTORS",
  "REJECT",
  "BLOCKMAP",
  "BEHAVIOR",
  "SCRIPTS",
  "LEAFS",
  "LIGHTS",
  "MACROS",
  "ZNODES",
  "DIALOGUE",
]);

/** `S_START`..`S_END` and doubled `SS_` forms name these namespaces. */
const NAMESPACES: Readonly<Record<string, string>> = {
  S: "sprites",
  F: "flats",
  P: "patches",
  TX: "textures",
  C: "colormaps",
  A: "acs",
  HI: "hires",
  V: "voices",
};

const namespaceOf = (marker: string): string | null => {
  const match = /^([A-Z]{1,2})_(START|END)$/u.exec(marker);
  if (match === null) return null;
  const prefix = match[1] ?? "";
  return (
    NAMESPACES[prefix] ??
    (prefix.length === 2 && prefix[0] === prefix[1]
      ? (NAMESPACES[prefix[0] ?? ""] ?? null)
      : null)
  );
};

interface Lump {
  readonly name: string;
  readonly offset: number;
  readonly size: number;
}

/** Group lumps into maps and marker namespaces, as Doom source ports do. */
const groupLumps = (lumps: readonly Lump[]): (string | null)[] => {
  const groups: (string | null)[] = [];
  let map: string | null = null;
  let udmf = false;
  let namespace: string | null = null;
  lumps.forEach((lump, index) => {
    const next = lumps[index + 1]?.name;
    if (map !== null && (udmf ? true : MAP_LUMPS.has(lump.name))) {
      groups.push(map);
      if (lump.name === "ENDMAP") {
        map = null;
        udmf = false;
      }
      return;
    }
    map = null;
    if (next === "THINGS" || next === "TEXTMAP") {
      map = lump.name;
      udmf = next === "TEXTMAP";
      groups.push(`map:${lump.name}`);
      return;
    }
    // F1_START, P2_END and similar sub-markers sit inside a namespace.
    if (/^[A-Z]{1,2}\d_(?:START|END)$/u.test(lump.name)) {
      groups.push("marker");
      return;
    }
    const marker = namespaceOf(lump.name);
    if (marker !== null) {
      namespace = lump.name.endsWith("_START") ? marker : null;
      groups.push("marker");
      return;
    }
    groups.push(namespace);
  });
  return groups;
};

/** Parse a Doom-engine IWAD or PWAD directory. */
export const readDoomWad = (bytes: Buffer): ArchiveListing => {
  const kind = bytes.toString("latin1", 0, 4);
  const count = bytes.readInt32LE(4);
  const directory = bytes.readInt32LE(8);
  if (count < 0 || directory < 12 || directory + count * 16 > bytes.length)
    archiveFail("The WAD directory lies outside the file.");
  const lumps: Lump[] = Array.from({ length: count }, (_, index) => {
    const at = directory + index * 16;
    const offset = bytes.readInt32LE(at);
    const size = bytes.readInt32LE(at + 4);
    const name = bytes
      .toString("latin1", at + 8, at + 16)
      .replace(/\0.*$/su, "");
    if (offset < 0 || size < 0 || offset + size > bytes.length)
      archiveFail(`Lump ${name} lies outside the file.`);
    return { name, offset, size };
  });
  const groups = groupLumps(lumps);
  const seen = new Map<string, number>();
  const entries: ArchiveEntry[] = lumps.map((lump, index) => {
    const raw = groups[index] ?? null;
    const group = raw?.startsWith("map:") === true ? "map" : raw;
    const base =
      raw === null || raw === "marker" || raw.startsWith("map:")
        ? lump.name
        : `${raw}/${lump.name}`;
    const occurrence = (seen.get(base) ?? 0) + 1;
    seen.set(base, occurrence);
    return {
      path: occurrence === 1 ? base : `${base}#${String(occurrence)}`,
      size: lump.size,
      parts:
        lump.size === 0
          ? []
          : [{ kind: "file", offset: lump.offset, length: lump.size }],
      encrypted: false,
      removed: false,
      group,
      checksum: null,
    };
  });
  const maps = groups.filter(
    (group) => group?.startsWith("map:") === true,
  ).length;
  return {
    format: "doom_wad",
    version: kind,
    embeddedAt: null,
    engineVersion: null,
    flags: [],
    entries,
    notes: [`${String(maps)} map(s); map lumps are listed as MAPNAME/LUMP.`],
  };
};
