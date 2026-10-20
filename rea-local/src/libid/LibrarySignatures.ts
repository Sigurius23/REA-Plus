import { basename } from "node:path";

import { archiveMembers, isArchive } from "./ArchiveMembers.js";
import { readRelocatableObject, type ObjectReference } from "./ObjectFiles.js";
import type { TargetImage } from "./TargetImage.js";

/**
 * A library function's whole body as a byte pattern: every byte the linker
 * keeps must match, the relocated ones are wildcards. Signatures are found
 * by an 8-byte anchor, the first fully fixed run.
 */
export interface Signature {
  readonly name: string;
  readonly local: boolean;
  readonly library: string;
  readonly member: string;
  /** Library, member and section: functions sharing it keep their relative offsets. */
  readonly section: string;
  readonly offset: number;
  readonly bytes: Buffer;
  readonly mask: Uint8Array;
  readonly fixed: number;
  readonly anchor: number;
  readonly key: number;
  readonly references: readonly ObjectReference[];
}

export interface LibraryFacts {
  readonly path: string;
  readonly kind: "archive" | "object";
  readonly format: "elf" | "coff" | "unknown";
  readonly machine: string;
  readonly members: number;
  readonly unreadable: number;
  readonly functions: number;
  /** Functions with fewer fixed bytes than `min_bytes`, or no fixed anchor. */
  readonly short: number;
  readonly signatures: readonly Signature[];
}

const ANCHOR = 8;

/** Hash of the 8 bytes at an offset; collisions are settled by full comparison. */
export const anchorKey = (data: Buffer, at: number): number =>
  (data.readUInt32LE(at) ^ Math.imul(data.readUInt32LE(at + 4), 0x9e3779b1)) >>>
  0;

const anchorOf = (mask: Uint8Array): number => {
  let run = 0;
  for (let at = 0; at < mask.length; at += 1) {
    run = mask[at] === 1 ? run + 1 : 0;
    if (run === ANCHOR) return at - ANCHOR + 1;
  }
  return -1;
};

/** Read one static library or object file into signatures. */
export const librarySignatures = (
  path: string,
  data: Buffer,
  options: { readonly minBytes: number; readonly includeLocal: boolean },
): LibraryFacts => {
  const members = archiveMembers(data, basename(path));
  const signatures: Signature[] = [];
  let unreadable = 0;
  let functions = 0;
  let short = 0;
  let format: LibraryFacts["format"] = "unknown";
  let machine = "unknown";
  for (const member of members) {
    const object = readRelocatableObject(member.data);
    if (object === null) {
      unreadable += 1;
      continue;
    }
    format = object.format;
    machine = object.machine;
    for (const fn of object.functions) {
      if (fn.local && !options.includeLocal) continue;
      functions += 1;
      const mask = new Uint8Array(fn.bytes.length).fill(1);
      for (const [start, end] of fn.wildcards)
        mask.fill(0, Math.max(0, start), Math.min(mask.length, end));
      const fixed = mask.reduce((sum, bit) => sum + bit, 0);
      const anchor = anchorOf(mask);
      if (fixed < options.minBytes || anchor < 0) {
        short += 1;
        continue;
      }
      signatures.push({
        name: fn.name,
        local: fn.local,
        library: path,
        member: member.name,
        section: `${path}\0${member.name}\0${String(fn.section)}`,
        offset: fn.offset,
        bytes: fn.bytes,
        mask,
        fixed,
        anchor,
        key: anchorKey(fn.bytes, anchor),
        references: fn.references,
      });
    }
  }
  return {
    path,
    kind: isArchive(data) ? "archive" : "object",
    format,
    machine,
    members: members.length,
    unreadable,
    functions,
    short,
    signatures,
  };
};

export interface Hit {
  readonly address: bigint;
  readonly signature: Signature;
}

const matchesAt = (bytes: Buffer, start: number, signature: Signature) => {
  const { bytes: pattern, mask } = signature;
  for (let at = 0; at < pattern.length; at += 1)
    if (mask[at] === 1 && bytes[start + at] !== pattern[at]) return false;
  return true;
};

/** Every place in the image's code where a signature's fixed bytes all match. */
export const scanImage = (
  image: TargetImage,
  signatures: readonly Signature[],
  signal?: AbortSignal,
): Hit[] => {
  const index = new Map<number, Signature[]>();
  for (const signature of signatures)
    index.set(signature.key, [...(index.get(signature.key) ?? []), signature]);
  const hits: Hit[] = [];
  for (const region of image.regions) {
    if (!region.executable) continue;
    const { bytes } = region;
    for (let at = 0; at + ANCHOR <= bytes.length; at += 1) {
      if (at % 1_000_000 === 0) signal?.throwIfAborted();
      const candidates = index.get(anchorKey(bytes, at));
      if (candidates === undefined) continue;
      for (const signature of candidates) {
        const start = at - signature.anchor;
        if (
          start < 0 ||
          start + signature.bytes.length > bytes.length ||
          !matchesAt(bytes, start, signature)
        )
          continue;
        hits.push({ address: region.address + BigInt(start), signature });
      }
    }
  }
  return hits;
};
