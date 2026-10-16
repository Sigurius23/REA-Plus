import { constants } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import { join, relative, sep } from "node:path";

import { readStableArtifact } from "../artifacts/readStableArtifact.js";

/** RPG Maker data that cannot be read as a project; reported as an input error. */
export class RpgMakerFormatError extends Error {
  override readonly name = "RpgMakerFormatError";
}

const MAX_DATA_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_DATA_BYTES = 768 * 1024 * 1024;
const MAX_WALKED_FILES = 200_000;

export interface ProjectLocation {
  /** Caller-selected folder; every reported path is relative to it. */
  readonly root: string;
  /** Folder holding data/, js/, img/ and audio/. */
  readonly base: string;
  readonly layout: "deployed-www" | "root";
}

export interface ReadFile {
  readonly path: string;
  readonly bytes: Buffer;
  readonly sha256: string;
}

/** Whether a regular file is there; a symlink in its place is refused. */
const isFile = async (path: string): Promise<boolean> => {
  let stat;
  try {
    stat = await lstat(path);
  } catch {
    return false;
  }
  if (stat.isSymbolicLink())
    throw new RpgMakerFormatError(
      `Refusing a symlink where game data is expected: ${path}`,
    );
  return stat.isFile();
};

/** Find data/System.json under www/ (deployed MV) or at the top. */
export const locateProject = async (root: string): Promise<ProjectLocation> => {
  const stat = await lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new RpgMakerFormatError(
      `Expected a game directory without a symlink: ${root}`,
    );
  for (const [base, layout] of [
    [join(root, "www"), "deployed-www"],
    [root, "root"],
  ] as const)
    if (await isFile(join(base, "data", "System.json")))
      return { root, base, layout };
  throw new RpgMakerFormatError(
    "No data/System.json or www/data/System.json: not an RPG Maker MV/MZ game folder.",
  );
};

/** Relative, forward-slash path from the selected folder. */
export const relativeName = (location: ProjectLocation, path: string): string =>
  relative(location.root, path).split(sep).join("/");

/** Bounded, symlink-refusing reads that also keep a running byte budget. */
export class ProjectReader {
  #total = 0;

  constructor(
    readonly location: ProjectLocation,
    private readonly signal: AbortSignal | undefined,
  ) {}

  async exists(path: string): Promise<boolean> {
    return isFile(path);
  }

  async readData(path: string): Promise<ReadFile> {
    const { bytes, sha256 } = await readStableArtifact(
      path,
      MAX_DATA_FILE_BYTES,
      this.signal,
    );
    this.#total += bytes.length;
    if (this.#total > MAX_TOTAL_DATA_BYTES)
      throw new RpgMakerFormatError(
        `Game data exceeds ${String(MAX_TOTAL_DATA_BYTES)} bytes.`,
      );
    return { path: relativeName(this.location, path), bytes, sha256 };
  }

  async readJson(path: string): Promise<{ file: ReadFile; value: unknown }> {
    const file = await this.readData(path);
    try {
      return {
        file,
        value: JSON.parse(file.bytes.toString("utf8").replace(/^﻿/u, "")),
      };
    } catch (cause) {
      throw new RpgMakerFormatError(`${file.path} is not JSON`, { cause });
    }
  }

  /** The first bytes of a file, opened without following a symlink. */
  async head(path: string, length: number): Promise<Buffer> {
    this.signal?.throwIfAborted();
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buffer, 0, length, 0);
      return buffer.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }

  async readWhole(path: string, maximumBytes: number): Promise<ReadFile> {
    const { bytes, sha256 } = await readStableArtifact(
      path,
      maximumBytes,
      this.signal,
    );
    return { path: relativeName(this.location, path), bytes, sha256 };
  }

  /** Symlinks met while walking asset and save folders; they are never followed. */
  skippedLinks = 0;

  /** Regular files under a folder with their sizes, sorted by path. */
  async walk(
    directory: string,
  ): Promise<{ files: { path: string; bytes: number }[]; truncated: boolean }> {
    const files: { path: string; bytes: number }[] = [];
    const pending = [directory];
    let truncated = false;
    while (pending.length > 0 && !truncated) {
      this.signal?.throwIfAborted();
      const current = pending.pop() ?? directory;
      let entries;
      try {
        entries = await opendir(current);
      } catch {
        continue;
      }
      for await (const entry of entries) {
        const path = join(current, entry.name);
        if (entry.isSymbolicLink()) this.skippedLinks += 1;
        else if (entry.isDirectory()) pending.push(path);
        else if (entry.isFile()) {
          if (files.length >= MAX_WALKED_FILES) {
            truncated = true;
            break;
          }
          files.push({ path, bytes: (await lstat(path)).size });
        }
      }
    }
    files.sort((left, right) => (left.path < right.path ? -1 : 1));
    return { files, truncated };
  }
}
