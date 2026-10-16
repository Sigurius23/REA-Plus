import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

import { hashReadable } from "../artifacts/ArtifactHash.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { InspectIl2CppMetadataInput } from "../domain/il2cpp/il2cppMetadata.js";
import { Il2CppInputRejected } from "./R2UnityFailures.js";
import { R2UNITY_LIMITS } from "./R2UnityRelease.js";

const METADATA_MAGIC = 0xfab11baf;

export interface FileIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

/** Content identities of the selected metadata and optional native binary. */
export interface Selection {
  readonly metadata: FileIdentity;
  readonly binary: FileIdentity | null;
}

/** Hash one regular file without following symlinks or admitting changes. */
const identifyFile = async (
  path: string,
  field: "metadata_path" | "binary_path",
  maximumBytes: number,
  signal?: AbortSignal,
) => {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile())
    throw new Il2CppInputRejected(
      field,
      `Expected a regular file without a symlink: ${path}`,
    );
  if (before.size > BigInt(maximumBytes))
    throw new Il2CppInputRejected(
      field,
      `${path} exceeds the ${String(maximumBytes)}-byte limit.`,
    );
  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const opened = await handle.stat({ bigint: true });
    if (opened.ino !== before.ino || opened.dev !== before.dev)
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed before open: ${path}`,
      );
    const hashed = await hashReadable(
      handle.createReadStream({ autoClose: false }),
      signal,
    );
    const after = await handle.stat({ bigint: true });
    if (
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      BigInt(hashed.bytes) !== before.size
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed while it was read: ${path}`,
      );
    return {
      identity: { path, sha256: hashed.sha256, bytes: hashed.bytes },
      prefix: hashed.prefix,
    };
  } finally {
    await handle.close();
  }
};

/** Admit the metadata header before r2unity sees it, for precise errors. */
export const identifySelection = async (
  input: InspectIl2CppMetadataInput,
  signal?: AbortSignal,
): Promise<Selection> => {
  if (input.code_registration !== undefined && input.binary_path === undefined)
    throw new Il2CppInputRejected(
      "code_registration",
      "code_registration overrides pointer recovery in binary_path; select the binary too.",
    );
  const metadata = await identifyFile(
    input.metadata_path,
    "metadata_path",
    R2UNITY_LIMITS.metadataBytes,
    signal,
  );
  const header = metadata.prefix;
  if (header.length < 8 || header.readUInt32LE(0) !== METADATA_MAGIC)
    throw new Il2CppInputRejected(
      "metadata_path",
      "Not IL2CPP global-metadata.dat: the 0xFAB11BAF magic is missing. Encrypted or obfuscated metadata must be decrypted first.",
    );
  const wire = header.readInt32LE(4);
  if (wire < 24 || wire > 39 || (wire > 35 && wire < 38))
    throw new Il2CppInputRejected(
      "metadata_path",
      `Metadata wire version ${String(wire)} is outside r2unity 1.2's supported 24.1-35 and 38-39.`,
    );
  const binary =
    input.binary_path === undefined
      ? null
      : (
          await identifyFile(
            input.binary_path,
            "binary_path",
            R2UNITY_LIMITS.binaryBytes,
            signal,
          )
        ).identity;
  if (binary !== null && binary.sha256 === metadata.identity.sha256)
    throw new Il2CppInputRejected(
      "binary_path",
      "binary_path must be the native IL2CPP library, not the metadata file.",
    );
  return { metadata: metadata.identity, binary };
};
