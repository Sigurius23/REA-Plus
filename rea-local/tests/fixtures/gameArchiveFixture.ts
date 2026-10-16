import { createHash } from "node:crypto";
import { crc32, deflateSync } from "node:zlib";

/**
 * Game archives built in source. Layouts follow the writers that produce
 * real files: Godot's PCKPacker (3.6, 4.4, 4.5), Ren'Py's archiver, Valve's
 * VPK directory format and the Doom WAD directory.
 */

export interface FixtureFile {
  readonly path: string;
  readonly data: Buffer;
}

const u32 = (value: number) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};

const u64 = (value: number) => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
};

const pad = (length: number, alignment: number) =>
  Buffer.alloc((alignment - (length % alignment)) % alignment);

export const md5 = (data: Buffer) =>
  createHash("md5").update(data).digest("hex");
export const sha256 = (data: Buffer) =>
  createHash("sha256").update(data).digest("hex");

export const GAME_FILES: readonly FixtureFile[] = [
  {
    path: "scenes/main.gd",
    data: Buffer.from('extends Node\n\nfunc _ready():\n\tprint("hello")\n'),
  },
  {
    path: "project.binary",
    data: Buffer.from([0x45, 0x43, 0x46, 0x47, 0, 1, 2, 3, 0xff]),
  },
  {
    path: "data/levels.json",
    data: Buffer.from('{"name": "Ünïcödé level"}\n'),
  },
  { path: "data/empty.txt", data: Buffer.alloc(0) },
];

/** Godot pack formats 1 (3.x), 2 (4.0-4.4) and 3 (4.5+). */
export const createGodotPack = (options: {
  readonly version: 1 | 2 | 3;
  readonly engine: readonly [number, number, number];
  readonly files?: readonly FixtureFile[];
  readonly encryptedPaths?: readonly string[];
  readonly removedPaths?: readonly string[];
  readonly encryptedDirectory?: boolean;
  readonly recordMd5?: boolean;
}): Buffer => {
  const files = options.files ?? GAME_FILES;
  const { version } = options;
  const headerSize = version === 1 ? 84 : version === 2 ? 96 : 104;
  const removed = options.removedPaths ?? [];
  const directoryEntry = (path: string) => {
    const name = Buffer.from(`res://${path}`, "utf8");
    const padded =
      version === 1 ? name : Buffer.concat([name, pad(name.length, 4)]);
    return {
      name: padded,
      size: 4 + padded.length + 32 + (version === 1 ? 0 : 4),
    };
  };
  const directorySize =
    4 +
    [...files.map(({ path }) => path), ...removed].reduce(
      (sum, path) => sum + directoryEntry(path).size,
      0,
    );
  const dataStart =
    headerSize + directorySize + pad(headerSize + directorySize, 32).length;
  const blobs: Buffer[] = [];
  let at = 0;
  const offsets = files.map(({ data }) => {
    const offset = at;
    const padded = Buffer.concat([data, pad(data.length, 32)]);
    blobs.push(padded);
    at += padded.length;
    return offset;
  });
  const flags =
    version === 1
      ? 0
      : (options.encryptedDirectory === true ? 1 : 0) | (version === 3 ? 2 : 0);
  const header = [
    Buffer.from("GDPC"),
    u32(version),
    ...options.engine.map(u32),
  ];
  if (version === 1) header.push(Buffer.alloc(64));
  else if (version === 2)
    header.push(u32(flags), u64(dataStart), Buffer.alloc(64));
  else
    header.push(u32(flags), u64(dataStart), u64(headerSize), Buffer.alloc(64));
  const directory: Buffer[] = [u32(files.length + removed.length)];
  const record = (
    path: string,
    offset: number,
    data: Buffer,
    fileFlags: number,
  ) => {
    const { name } = directoryEntry(path);
    directory.push(
      u32(name.length),
      name,
      u64(version === 1 ? dataStart + offset : offset),
      u64(data.length),
      options.recordMd5 === false
        ? Buffer.alloc(16)
        : Buffer.from(md5(data), "hex"),
    );
    if (version !== 1) directory.push(u32(fileFlags));
  };
  files.forEach(({ path, data }, index) =>
    record(
      path,
      offsets[index] ?? 0,
      data,
      options.encryptedPaths?.includes(path) === true ? 1 : 0,
    ),
  );
  for (const path of removed) record(path, 0, Buffer.alloc(0), 2);
  const head = Buffer.concat([...header, ...directory]);
  return Buffer.concat([head, pad(head.length, 32), ...blobs]);
};

/** Append a pack to an executable the way Godot exports self-contained games. */
export const embedInExecutable = (pack: Buffer, executable: Buffer): Buffer =>
  Buffer.concat([
    executable,
    pad(executable.length, 8),
    pack,
    u64(pack.length),
    Buffer.from("GDPC"),
  ]);

/** A protocol-2 pickle of {name: [(offset, length, prefix)]}, as Python 2 Ren'Py wrote it. */
const renpyIndex = (
  entries: readonly {
    name: string;
    offset: number;
    length: number;
    prefix: Buffer;
  }[],
  withPrefix: boolean,
): Buffer => {
  const integer = (value: number) =>
    value < 0x8000_0000
      ? Buffer.concat([Buffer.from([0x4a]), u32(value)])
      : Buffer.concat([Buffer.from([0x8a, 5]), u64(value).subarray(0, 5)]);
  const parts: Buffer[] = [Buffer.from([0x80, 2, 0x7d, 0x28])];
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    parts.push(
      Buffer.from([0x58]),
      u32(name.length),
      name,
      Buffer.from([0x5d, 0x28]),
    );
    parts.push(integer(entry.offset), integer(entry.length));
    if (withPrefix)
      parts.push(
        Buffer.from([0x55, entry.prefix.length]),
        entry.prefix,
        Buffer.from([0x87]),
      );
    else parts.push(Buffer.from([0x86]));
    parts.push(Buffer.from([0x65]));
  }
  parts.push(Buffer.from([0x75, 0x2e]));
  return Buffer.concat(parts);
};

/** Ren'Py RPA-3.0 (XOR key) or RPA-2.0 archive with optional entry prefixes. */
export const createRenpyArchive = (options: {
  readonly version: "2.0" | "3.0";
  readonly key?: number;
  readonly files?: readonly (FixtureFile & { prefix?: number })[];
}): Buffer => {
  const files: readonly (FixtureFile & { prefix?: number })[] =
    options.files ?? GAME_FILES;
  const key = options.version === "2.0" ? 0 : (options.key ?? 0x42424242);
  const header = options.version === "2.0" ? 25 : 34;
  const chunks: Buffer[] = [];
  let at = header;
  const entries = files.map(({ path, data, prefix = 0 }) => {
    const filler = Buffer.from("Made with Ren'Py.");
    chunks.push(filler, data.subarray(prefix));
    at += filler.length;
    const offset = at;
    at += data.length - prefix;
    return {
      name: path,
      offset: (offset ^ key) >>> 0,
      length: ((data.length - prefix) ^ key) >>> 0,
      prefix: data.subarray(0, prefix),
    };
  });
  const index = deflateSync(renpyIndex(entries, options.version === "3.0"));
  const offsetText = at.toString(16).padStart(16, "0");
  const line =
    options.version === "2.0"
      ? `RPA-2.0 ${offsetText}\n`
      : `RPA-3.0 ${offsetText} ${key.toString(16).padStart(8, "0")}\n`;
  return Buffer.concat([Buffer.from(line, "latin1"), ...chunks, index]);
};

/** Valve VPK directory plus sibling chunks; `archive` 0x7fff keeps data in the directory file. */
export const createValveVpk = (options: {
  readonly version: 1 | 2;
  readonly files: readonly (FixtureFile & {
    preload?: number;
    archive?: number;
  })[];
}): { directory: Buffer; chunks: ReadonlyMap<number, Buffer> } => {
  const byExtension = new Map<
    string,
    Map<string, (typeof options.files)[number][]>
  >();
  for (const file of options.files) {
    const slash = file.path.lastIndexOf("/");
    const directory = slash < 0 ? " " : file.path.slice(0, slash);
    const name = file.path.slice(slash + 1);
    const dot = name.lastIndexOf(".");
    const extension = dot < 0 ? " " : name.slice(dot + 1);
    const directories = byExtension.get(extension) ?? new Map();
    byExtension.set(extension, directories);
    directories.set(directory, [...(directories.get(directory) ?? []), file]);
  }
  const tree: Buffer[] = [];
  const embedded: Buffer[] = [];
  let embeddedSize = 0;
  const chunks = new Map<number, Buffer>();
  const text = (value: string) => Buffer.from(`${value}\0`, "utf8");
  for (const [extension, directories] of byExtension) {
    tree.push(text(extension));
    for (const [directory, files] of directories) {
      tree.push(text(directory));
      for (const file of files) {
        const name = file.path.slice(file.path.lastIndexOf("/") + 1);
        const stem =
          extension === " " ? name : name.slice(0, name.lastIndexOf("."));
        const preload = file.preload ?? 0;
        const rest = file.data.subarray(preload);
        const archive = file.archive ?? 0x7fff;
        let offset: number;
        if (archive === 0x7fff) {
          offset = embeddedSize;
          embedded.push(rest);
          embeddedSize += rest.length;
        } else {
          const chunk = chunks.get(archive) ?? Buffer.alloc(0);
          offset = chunk.length;
          chunks.set(archive, Buffer.concat([chunk, rest]));
        }
        const record = Buffer.alloc(18);
        record.writeUInt32LE(crc32(file.data), 0);
        record.writeUInt16LE(preload, 4);
        record.writeUInt16LE(archive, 6);
        record.writeUInt32LE(rest.length === 0 ? 0 : offset, 8);
        record.writeUInt32LE(rest.length, 12);
        record.writeUInt16LE(0xffff, 16);
        tree.push(text(stem), record, file.data.subarray(0, preload));
      }
      tree.push(text(""));
    }
    tree.push(text(""));
  }
  tree.push(text(""));
  const treeBytes = Buffer.concat(tree);
  const header = [u32(0x55aa1234), u32(options.version), u32(treeBytes.length)];
  // Version 2 ends with the "other MD5" section: tree, archive-MD5 section, whole file.
  const trailer =
    options.version === 2
      ? [
          Buffer.from(md5(treeBytes), "hex"),
          Buffer.from(md5(Buffer.alloc(0)), "hex"),
          Buffer.alloc(16),
        ]
      : [];
  if (options.version === 2)
    header.push(u32(embeddedSize), u32(0), u32(48), u32(0));
  return {
    directory: Buffer.concat([...header, treeBytes, ...embedded, ...trailer]),
    chunks,
  };
};

/** Doom IWAD/PWAD: lumps, then the 16-byte directory entries. */
export const createDoomWad = (
  kind: "IWAD" | "PWAD",
  lumps: readonly { name: string; data?: Buffer }[],
): Buffer => {
  const data: Buffer[] = [];
  const directory: Buffer[] = [];
  let at = 12;
  for (const lump of lumps) {
    const bytes = lump.data ?? Buffer.alloc(0);
    const entry = Buffer.alloc(16);
    entry.writeInt32LE(bytes.length === 0 ? 0 : at, 0);
    entry.writeInt32LE(bytes.length, 4);
    entry.write(lump.name, 8, "latin1");
    directory.push(entry);
    data.push(bytes);
    at += bytes.length;
  }
  const header = Buffer.alloc(12);
  header.write(kind, 0, "latin1");
  header.writeInt32LE(lumps.length, 4);
  header.writeInt32LE(at, 8);
  return Buffer.concat([header, ...data, ...directory]);
};

const lump = (name: string, size: number, fill: number) => ({
  name,
  data: Buffer.alloc(size, fill),
});

/** A PWAD with a binary-format map, a UDMF map, sprites with sub-markers and a duplicate lump. */
export const DOOM_LUMPS = [
  lump("PLAYPAL", 768, 1),
  { name: "MAP01" },
  lump("THINGS", 20, 2),
  lump("LINEDEFS", 28, 3),
  lump("SIDEDEFS", 30, 4),
  lump("VERTEXES", 8, 5),
  lump("SECTORS", 26, 6),
  { name: "MAP02" },
  {
    name: "TEXTMAP",
    data: Buffer.from(
      'namespace = "zdoom";\nthing { x = 0; y = 0; type = 1; }\n',
    ),
  },
  lump("ZNODES", 12, 7),
  { name: "ENDMAP" },
  { name: "S_START" },
  { name: "S1_START" },
  lump("TROOA1", 40, 8),
  { name: "S1_END" },
  lump("TROOB1", 40, 9),
  { name: "S_END" },
  lump("DEHACKED", 15, 0x41),
  lump("DEHACKED", 15, 0x42),
] as const;
