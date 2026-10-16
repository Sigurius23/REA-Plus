import {
  archiveFail,
  range,
  type ArchiveEntry,
  type ArchiveListing,
  type EntryPart,
} from "./GameArchiveTypes.js";

const SIGNATURE = 0x55aa1234;
const IN_DIRECTORY_FILE = 0x7fff;
const MAX_ENTRIES = 5_000_000;

export const isValveVpk = (bytes: Buffer): boolean =>
  bytes.length >= 12 && bytes.readUInt32LE(0) === SIGNATURE;

/** `pak01_dir.vpk` keeps its data in `pak01_000.vpk`, `pak01_001.vpk` and so on. */
const chunkName = (fileName: string, index: number): string =>
  `${fileName.replace(/(?:_dir)?\.vpk$/iu, "")}_${String(index).padStart(3, "0")}.vpk`;

class TreeCursor {
  constructor(
    private readonly bytes: Buffer,
    public at: number,
    private readonly end: number,
  ) {}

  string(): string {
    const stop = this.bytes.indexOf(0, this.at);
    if (stop < 0 || stop >= this.end)
      archiveFail("A VPK tree string is not terminated.");
    const value = this.bytes.toString("utf8", this.at, stop);
    this.at = stop + 1;
    return value;
  }

  take(length: number): Buffer {
    if (this.at + length > this.end)
      archiveFail("A VPK tree entry runs past the tree.");
    const value = this.bytes.subarray(this.at, this.at + length);
    this.at += length;
    return value;
  }
}

const joinPath = (directory: string, name: string, extension: string): string =>
  `${directory === " " || directory === "" ? "" : `${directory}/`}${name}${extension === " " || extension === "" ? "" : `.${extension}`}`;

interface Placement {
  readonly dataStart: number;
  readonly fileName: string;
  readonly chunks: Set<string>;
}

/** One file's 18-byte record, its preload bytes, and where its data lives. */
const readEntry = (
  tree: TreeCursor,
  path: string,
  { dataStart, fileName, chunks }: Placement,
): ArchiveEntry => {
  const fields = tree.take(18);
  const crc = fields.readUInt32LE(0);
  const preload = fields.readUInt16LE(4);
  const archive = fields.readUInt16LE(6);
  const offset = fields.readUInt32LE(8);
  const length = fields.readUInt32LE(12);
  if (fields.readUInt16LE(16) !== 0xffff)
    archiveFail("A VPK entry is missing its terminator.");
  const parts: EntryPart[] = [];
  if (preload > 0) parts.push({ kind: "inline", bytes: tree.take(preload) });
  if (length > 0 && archive === IN_DIRECTORY_FILE)
    parts.push({ kind: "file", offset: dataStart + offset, length });
  else if (length > 0) {
    const file = chunkName(fileName, archive);
    chunks.add(file);
    parts.push({ kind: "external", file, offset, length });
  }
  return {
    path,
    size: preload + length,
    parts,
    encrypted: false,
    removed: false,
    group: null,
    checksum: { algorithm: "crc32", value: crc.toString(16).padStart(8, "0") },
  };
};

/** Parse a Valve VPK v1/v2 directory (Source and Source 2 games). */
export const readValveVpk = (
  bytes: Buffer,
  fileName: string,
): ArchiveListing => {
  const version = bytes.readUInt32LE(4);
  if (version !== 1 && version !== 2)
    archiveFail(`VPK version ${String(version)} is not supported.`);
  const treeSize = bytes.readUInt32LE(8);
  const headerSize = version === 2 ? 28 : 12;
  range(bytes, 0, headerSize + treeSize, "VPK directory tree");
  const dataStart = headerSize + treeSize;
  const tree = new TreeCursor(bytes, headerSize, dataStart);
  const entries: ArchiveEntry[] = [];
  const chunks = new Set<string>();
  const place = { dataStart, fileName, chunks };
  for (
    let extension = tree.string();
    extension !== "";
    extension = tree.string()
  )
    for (
      let directory = tree.string();
      directory !== "";
      directory = tree.string()
    )
      for (let name = tree.string(); name !== ""; name = tree.string()) {
        if (entries.length >= MAX_ENTRIES) archiveFail("Too many VPK entries.");
        entries.push(
          readEntry(tree, joinPath(directory, name, extension), place),
        );
      }
  const notes =
    chunks.size === 0
      ? []
      : [
          `Entry data lives in ${String(chunks.size)} sibling archive(s) such as ${[...chunks][0] ?? ""}; REA+ reads only the selected file.`,
        ];
  if (version === 2) {
    const sections = [12, 16, 20, 24].map((at) => bytes.readUInt32LE(at));
    notes.push(
      `VPK 2 sections: ${String(sections[0])} bytes of embedded data, ${String(sections[1])} of archive MD5s, ${String(sections[2])} of other MD5s, ${String(sections[3])} of signature.`,
    );
  }
  return {
    format: "valve_vpk",
    version: String(version),
    embeddedAt: null,
    engineVersion: null,
    flags: chunks.size === 0 ? [] : ["multi_chunk"],
    entries,
    notes,
  };
};
