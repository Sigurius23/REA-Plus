import { writeFile } from "node:fs/promises";

import {
  TextReader,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipWriter,
} from "@zip.js/zip.js";

import type { ArtifactInventoryResult } from "../../src/domain/artifactGraph.js";

/** One ZIP member with exact text or byte content. */
export interface ZipMemberFixture {
  readonly name: string;
  readonly content: string | Uint8Array;
}

/** Write real ZIP members without touching the central-directory order. */
export const writeZipMembers = async (
  path: string,
  members: readonly ZipMemberFixture[],
): Promise<void> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const member of members)
    await writer.add(
      member.name,
      typeof member.content === "string"
        ? new TextReader(member.content)
        : new Uint8ArrayReader(member.content),
      { level: 0 },
    );
  await writeFile(path, await writer.close());
};

/**
 * Rename every ZIP record named `from` to `to` in place.
 *
 * zip.js refuses to produce duplicate names, so duplicate-name tests write
 * distinct names and then rename one. Equal-length names keep sizes and CRCs
 * valid.
 */
export const renameZipMember = (
  bytes: Buffer,
  from: string,
  to: string,
): Buffer => {
  if (Buffer.byteLength(from) !== Buffer.byteLength(to))
    throw new Error("ZIP member rename must preserve the name length");
  const length = Buffer.byteLength(from);
  for (const [signature, headerSize] of [
    [Buffer.from([0x50, 0x4b, 0x03, 0x04]), 30],
    [Buffer.from([0x50, 0x4b, 0x01, 0x02]), 46],
  ] as const) {
    let offset = bytes.indexOf(signature);
    let matched = 0;
    while (offset >= 0) {
      const observed = bytes
        .subarray(offset + headerSize, offset + headerSize + length)
        .toString();
      if (observed === from) {
        bytes.write(to, offset + headerSize);
        matched += 1;
      }
      offset = bytes.indexOf(signature, offset + 4);
    }
    if (matched === 0) throw new Error(`Expected a ZIP record named ${from}`);
  }
  return bytes;
};

/** Write real ZIP entries in the supplied central-directory order. */
export const writeOrderedZip = async (
  path: string,
  entries: readonly string[],
): Promise<void> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const entry of entries) {
    const directory = entry.endsWith("/");
    await writer.add(
      entry,
      directory ? undefined : new TextReader("evidence\n"),
      {
        directory,
        lastModDate: new Date("2020-01-01T00:00:00Z"),
      },
    );
  }
  await writeFile(path, await writer.close());
};

/** Express occurrence parents by logical path for structural assertions. */
export const artifactParentPaths = (
  inventory: ArtifactInventoryResult,
): Record<string, string | null> => {
  const paths = new Map(
    inventory.occurrences.map((item) => [
      item.occurrence_id,
      item.logical_path,
    ]),
  );
  return Object.fromEntries(
    inventory.occurrences.map((item) => [
      item.logical_path,
      item.parent_occurrence_id === null
        ? null
        : (paths.get(item.parent_occurrence_id) ?? "missing-parent"),
    ]),
  );
};

/** Require an explicitly observed occurrence in a real inventory. */
export const artifactOccurrenceAt = (
  inventory: ArtifactInventoryResult,
  path: string,
) => {
  const occurrence = inventory.occurrences.find(
    (item) => item.logical_path === path,
  );
  if (occurrence === undefined)
    throw new Error(`Missing inventory path: ${path}`);
  return occurrence;
};
