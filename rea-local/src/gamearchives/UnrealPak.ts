import {
  archiveFail,
  range,
  type ArchiveEntry,
  type ArchiveListing,
} from "./GameArchiveTypes.js";

const MAGIC = 0x5a6f12e1;
const MAX_ENTRIES = 5_000_000;

/** Footer layouts, newest first: size, where the magic sits, and the versions they hold. */
const FOOTERS: readonly {
  readonly size: number;
  readonly magicAt: number;
  readonly versions: readonly number[];
  readonly names: number;
}[] = [
  { size: 222, magicAt: 17, versions: [9], names: 5 },
  { size: 221, magicAt: 17, versions: [8, 10, 11], names: 5 },
  { size: 189, magicAt: 17, versions: [8], names: 4 },
  { size: 61, magicAt: 17, versions: [7], names: 0 },
  { size: 45, magicAt: 1, versions: [4, 5, 6], names: 0 },
  { size: 44, magicAt: 0, versions: [1, 2, 3], names: 0 },
];

interface PakVersion {
  readonly major: number;
  /** 8A packs store the compression index in one byte and four method names. */
  readonly label: string;
}

interface Footer {
  readonly version: PakVersion;
  readonly encryptedIndex: boolean;
  readonly indexOffset: number;
  readonly indexSize: number;
  readonly methods: readonly string[];
}

const toNumber = (value: bigint, what: string): number =>
  value > BigInt(Number.MAX_SAFE_INTEGER)
    ? archiveFail(`${what} is too large.`)
    : Number(value);

/** Find the footer by trying each layout from the end of the file. */
const readFooter = (bytes: Buffer): Footer | null => {
  for (const layout of FOOTERS) {
    const start = bytes.length - layout.size;
    if (start < 0) continue;
    if (bytes.readUInt32LE(start + layout.magicAt) !== MAGIC) continue;
    const major = bytes.readUInt32LE(start + layout.magicAt + 4);
    if (!layout.versions.includes(major)) continue;
    const at = start + layout.magicAt + 8;
    const label =
      major === 8 ? (layout.names === 4 ? "8A" : "8B") : String(major);
    const namesAt = at + 16 + 20 + (major === 9 ? 1 : 0);
    const methods = Array.from({ length: layout.names }, (_, index) =>
      bytes
        .toString("latin1", namesAt + index * 32, namesAt + index * 32 + 32)
        .replace(/\0.*$/su, ""),
    );
    return {
      version: { major, label },
      encryptedIndex: major >= 4 && bytes[start + (major >= 7 ? 16 : 0)] === 1,
      indexOffset: toNumber(bytes.readBigUInt64LE(at), "index offset"),
      indexSize: toNumber(bytes.readBigUInt64LE(at + 8), "index size"),
      methods,
    };
  }
  return null;
};

export const isUnrealPak = (bytes: Buffer): boolean =>
  bytes.length >= 44 && readFooter(bytes) !== null;

class PakCursor {
  constructor(
    private readonly bytes: Buffer,
    public at = 0,
  ) {}

  private take(length: number, what: string): number {
    if (length < 0 || this.at + length > this.bytes.length)
      archiveFail(`${what} runs past the end of the pak index.`);
    const start = this.at;
    this.at += length;
    return start;
  }

  u8 = (what: string) => this.bytes[this.take(1, what)] ?? 0;
  u32 = (what: string) => this.bytes.readUInt32LE(this.take(4, what));
  i32 = (what: string) => this.bytes.readInt32LE(this.take(4, what));
  u64 = (what: string) =>
    toNumber(this.bytes.readBigUInt64LE(this.take(8, what)), what);
  slice = (length: number, what: string) => {
    const start = this.take(length, what);
    return this.bytes.subarray(start, start + length);
  };

  /** Unreal FString: i32 length with NUL; negative lengths are UTF-16 code units. */
  string(what: string): string {
    const length = this.i32(`${what} length`);
    if (Math.abs(length) > 65_536)
      archiveFail(`${what} length is out of range.`);
    const text =
      length < 0
        ? this.slice(-length * 2, what).toString("utf16le")
        : this.slice(length, what).toString("utf8");
    return text.replace(/\0.*$/su, "");
  }
}

/** Methods before pak 8 are flags; from 8 on they index the footer's names. */
const methodName = (
  version: PakVersion,
  methods: readonly string[],
  value: number,
): string | null => {
  if (value === 0) return null;
  if (version.major < 8) {
    const flags = value & 0x0f;
    return flags & 1
      ? "Zlib"
      : flags & 2
        ? "Gzip"
        : flags & 4
          ? "Oodle"
          : `flags 0x${value.toString(16)}`;
  }
  return methods[value - 1] || `method ${String(value)}`;
};

interface RawEntry {
  readonly offset: number;
  readonly compressed: number;
  readonly uncompressed: number;
  readonly method: string | null;
  readonly hash: Buffer | null;
  readonly blocks: readonly { start: number; end: number }[];
  readonly flags: number;
}

/** FPakEntry as written in the legacy index and in front of each file's data. */
const readEntry = (
  cursor: PakCursor,
  version: PakVersion,
  methods: readonly string[],
): RawEntry => {
  const offset = cursor.u64("entry offset");
  const compressed = cursor.u64("compressed size");
  const uncompressed = cursor.u64("uncompressed size");
  const method = methodName(
    version,
    methods,
    version.label === "8A"
      ? cursor.u8("compression")
      : cursor.u32("compression"),
  );
  if (version.major === 1) cursor.u64("timestamp");
  const hash = cursor.slice(20, "hash");
  const blocks: { start: number; end: number }[] = [];
  let flags = 0;
  if (version.major >= 3) {
    if (method !== null) {
      const count = cursor.u32("block count");
      if (count > 1_000_000) archiveFail("Block count is out of range.");
      for (let index = 0; index < count; index += 1)
        blocks.push({
          start: cursor.u64("block start"),
          end: cursor.u64("block end"),
        });
    }
    flags = cursor.u8("entry flags");
    cursor.u32("compression block size");
  }
  return { offset, compressed, uncompressed, method, hash, blocks, flags };
};

/** Bit-packed FPakEntry of pak 10+ indexes (no hash; blocks are relative). */
const readEncoded = (
  cursor: PakCursor,
  version: PakVersion,
  methods: readonly string[],
): RawEntry => {
  const bits = cursor.u32("encoded entry");
  const methodIndex = (bits >>> 23) & 0x3f;
  const encrypted = (bits & (1 << 22)) !== 0;
  const blockCount = (bits >>> 6) & 0xffff;
  if ((bits & 0x3f) === 0x3f) cursor.u32("compression block size");
  const wide = (bit: number, what: string) =>
    (bits & (1 << bit)) !== 0 ? cursor.u32(what) : cursor.u64(what);
  const offset = wide(31, "entry offset");
  const uncompressed = wide(30, "uncompressed size");
  const compressed =
    methodIndex === 0 ? uncompressed : wide(29, "compressed size");
  const sizes =
    blockCount > 0 && (encrypted || blockCount !== 1)
      ? Array.from({ length: blockCount }, () => cursor.u32("block size"))
      : blockCount === 1
        ? [compressed]
        : [];
  return {
    offset,
    compressed,
    uncompressed,
    method: methodName(version, methods, methodIndex),
    hash: null,
    // Filled in from the in-data header, which also fixes where data starts.
    blocks: sizes.map((size) => ({ start: -1, end: size })),
    flags: encrypted ? 1 : 0,
  };
};

interface NamedEntry {
  readonly path: string;
  readonly entry: RawEntry;
}

/** Pak 10+: names come from the full directory index, entries from the encoded blob. */
const readModernIndex = (
  bytes: Buffer,
  cursor: PakCursor,
  footer: Footer,
): { entries: NamedEntry[]; notes: string[] } => {
  cursor.u64("path hash seed");
  const notes: string[] = [];
  if (cursor.u32("has path hash index") !== 0)
    cursor.slice(36, "path hash index");
  let directory: Buffer | null = null;
  if (cursor.u32("has full directory index") !== 0) {
    const offset = cursor.u64("directory offset");
    const size = cursor.u64("directory size");
    cursor.slice(20, "directory hash");
    directory = range(bytes, offset, size, "full directory index");
  }
  const encoded = cursor.slice(
    cursor.u32("encoded entries size"),
    "encoded entries",
  );
  const plainCount = cursor.u32("unencoded entry count");
  const plain = Array.from({ length: plainCount }, () =>
    readEntry(cursor, footer.version, footer.methods),
  );
  if (directory === null) {
    notes.push(
      "The pak has no full directory index; file names were stripped, so REA+ lists none.",
    );
    return { entries: [], notes };
  }
  const tree = new PakCursor(directory);
  const entries: NamedEntry[] = [];
  const directories = tree.u32("directory count");
  for (let index = 0; index < directories; index += 1) {
    const name = tree.string("directory name").replace(/^\//u, "");
    const files = tree.u32("file count");
    for (let file = 0; file < files; file += 1) {
      const fileName = tree.string("file name");
      const location = tree.i32("entry location");
      if (location === -0x8000_0000) continue;
      const entry =
        location < 0
          ? (plain[-location - 1] ??
            archiveFail("Unencoded entry index is out of range."))
          : readEncoded(
              new PakCursor(encoded, location),
              footer.version,
              footer.methods,
            );
      if (entries.length >= MAX_ENTRIES) archiveFail("Too many pak entries.");
      entries.push({ path: `${name}${fileName}`, entry });
    }
  }
  return { entries, notes };
};

/** Resolve where an entry's bytes start by reading the header stored before them. */
const locate = (
  bytes: Buffer,
  { path, entry }: NamedEntry,
  footer: Footer,
): ArchiveEntry => {
  const encrypted = (entry.flags & 1) !== 0;
  if ((entry.flags & 2) !== 0)
    return {
      path,
      size: 0,
      parts: [],
      encrypted,
      removed: true,
      group: null,
      checksum: null,
      compression: null,
    };
  const removed = false;
  const header = new PakCursor(bytes, entry.offset);
  const local = readEntry(header, footer.version, footer.methods);
  const dataStart = header.at;
  const base = footer.version.major >= 5 ? entry.offset : 0;
  const stored = encrypted ? (entry.compressed + 15) & ~15 : entry.compressed;
  range(bytes, dataStart, stored, `Data of ${path}`);
  const blocks =
    entry.method === null
      ? []
      : entry.blocks[0]?.start === -1
        ? (() => {
            let at = dataStart;
            return entry.blocks.map(({ end: size }) => {
              const block = { offset: at, length: size };
              at += encrypted ? (size + 15) & ~15 : size;
              return block;
            });
          })()
        : entry.blocks.map(({ start, end }) => ({
            offset: base + start,
            length: end - start,
          }));
  const hash = entry.hash ?? local.hash;
  return {
    path,
    size: entry.uncompressed,
    parts: removed ? [] : [{ kind: "file", offset: dataStart, length: stored }],
    encrypted,
    removed,
    group: null,
    checksum:
      hash === null || hash.every((byte) => byte === 0)
        ? null
        : { algorithm: "sha1", value: hash.toString("hex") },
    compression:
      entry.method === null ? null : { method: entry.method, blocks },
  };
};

/** Parse an Unreal Engine 4/5 .pak (versions 1-11); IoStore containers are separate. */
export const readUnrealPak = (bytes: Buffer): ArchiveListing => {
  const footer = readFooter(bytes) ?? archiveFail("No Unreal pak footer.");
  const flags = footer.encryptedIndex ? ["index_encrypted"] : [];
  const listing = {
    format: "unreal_pak" as const,
    version: footer.version.label,
    embeddedAt: null,
    engineVersion: null,
    flags,
  };
  if (footer.encryptedIndex)
    return {
      ...listing,
      entries: [],
      notes: [
        "The index is AES-256 encrypted with the game's key; REA+ lists no entries.",
      ],
    };
  const cursor = new PakCursor(
    range(bytes, footer.indexOffset, footer.indexSize, "pak index"),
  );
  const mountPoint = cursor.string("mount point");
  const count = cursor.u32("entry count");
  if (count > MAX_ENTRIES) archiveFail("Too many pak entries.");
  const read =
    footer.version.major >= 10
      ? readModernIndex(bytes, cursor, footer)
      : {
          entries: Array.from({ length: count }, () => ({
            path: cursor.string("file name"),
            entry: readEntry(cursor, footer.version, footer.methods),
          })),
          notes: [],
        };
  const entries = read.entries.map((named) => locate(bytes, named, footer));
  const methods = footer.methods.filter((name) => name !== "");
  return {
    ...listing,
    entries,
    notes: [
      `Mount point ${mountPoint}`,
      ...(methods.length > 0
        ? [`Compression methods: ${methods.join(", ")}.`]
        : []),
      ...read.notes,
    ],
  };
};
