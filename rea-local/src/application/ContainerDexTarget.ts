import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  mkdir,
  open,
  rename,
  rm,
  stat,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";

import {
  ArtifactReaderFailure,
  type ArtifactEntry,
} from "../artifacts/ArtifactReader.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { parseExecutableHeader } from "../domain/binaryTarget.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { BinaryTargetError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ZipPackageFormat } from "../domain/zipPackageFormat.js";
import { openRegularFile } from "../filesystem/RegularFile.js";

/**
 * Container DEX members are staged once beside their container and reused by
 * digest, so repeated resolutions and every DEX-capable provider read stable
 * bytes instead of re-extracting them. Streaming extraction is bounded by the
 * entry's declared central-directory size.
 */
const MEMBER_METADATA_READ_MAX_BYTES = 32 * 1024 * 1024;
const MAX_LISTED_MEMBER_NAMES = 40;

/** A DEX member selected inside a ZIP-package container. */
export interface ContainerMemberSelector {
  /** Container path as the caller supplied it, without a fragment. */
  readonly container: string;
  /** Exact archive entry name of the selected DEX, such as `classes2.dex`. */
  readonly member: string;
}

/**
 * Split a trailing `container.apk#member.dex` fragment. Filenames keep generic
 * `#` characters, so the resolver still verifies the container route and falls
 * back to the whole string before treating a fragment as a selection.
 */
export const splitContainerFragment = (
  input: string,
): ContainerMemberSelector | null => {
  const hash = input.lastIndexOf("#");
  if (hash <= 0 || hash === input.length - 1) return null;
  return {
    container: input.slice(0, hash),
    member: input.slice(hash + 1),
  };
};

/** Whether a whole fragment-form input also names an existing regular file. */
export const isExistingRegularFile = async (path: string): Promise<boolean> => {
  try {
    await access(path, constants.R_OK);
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
};

const throwIfCancelled = (signal?: AbortSignal): void => {
  if (signal?.aborted === true)
    throw new AnalysisCancelledError("resolve_binary_target");
};

/** Validate the selector shape before any I/O: members are top-level DEX entries. */
export const validateMemberSelector = (
  member: string,
  container: string,
): Result<null, BinaryTargetError> => {
  if (member.length === 0 || !/^[^/\x00]+$/.test(member))
    return err(
      new BinaryTargetError(
        container,
        `Container member selection requires one top-level entry name; received ${JSON.stringify(member)}.`,
      ),
    );
  if (member === "." || member === "..")
    return err(
      new BinaryTargetError(
        container,
        `Container member selection must name an archive entry; received ${JSON.stringify(member)}.`,
      ),
    );
  if (!member.toLowerCase().endsWith(".dex"))
    return err(
      new BinaryTargetError(
        container,
        `Container member selection only accepts .dex entries; ${JSON.stringify(member)} does not.`,
      ),
    );
  return ok(null);
};

/** One caller-selected DEX member inside a verified ZIP container. */
export interface ContainerDexResolution {
  /** Realpath'd, ZIP-verified container that the resolver already admitted. */
  readonly containerPath: string;
  /** SHA-256 of the container bytes, captured by the resolver. */
  readonly containerSha256: string;
  readonly format: ZipPackageFormat;
  readonly member: string;
  /** Caller-supplied staging root; absent uses `<container stem>-extracted/`. */
  readonly stagingDir: string | undefined;
  readonly hostArchitecture: NodeJS.Architecture;
  /** Identity used for targets synthesized from the extracted member bytes. */
  readonly sourcePath: string;
  /** Original caller input, kept for typed error paths. */
  readonly inputPath: string;
  readonly signal?: AbortSignal;
}

/**
 * Extract one named .dex member from an admitted ZIP container, stage it for
 * reuse by digest, classify the staged bytes, and return the standalone DEX
 * target every DEX-capable provider already accepts.
 */
export const extractContainerDexTarget = async (
  resolution: ContainerDexResolution,
): Promise<
  Result<BinaryTarget, BinaryTargetError | AnalysisCancelledError>
> => {
  const selector = validateMemberSelector(
    resolution.member,
    resolution.inputPath,
  );
  if (!selector.ok) return selector;
  try {
    return await extractSelectedDexMember(resolution);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) return err(cause);
    if (cause instanceof BinaryTargetError) return err(cause);
    if (cause instanceof ArtifactReaderFailure)
      return err(
        new BinaryTargetError(
          resolution.inputPath,
          `Container member could not be read: ${cause.message}`,
          { cause },
        ),
      );
    throw cause;
  }
};

const extractSelectedDexMember = async (
  resolution: ContainerDexResolution,
): Promise<
  Result<BinaryTarget, BinaryTargetError | AnalysisCancelledError>
> => {
  const reader = new ZipArtifactReader(
    resolution.containerPath,
    resolution.format,
    MEMBER_METADATA_READ_MAX_BYTES,
  );
  try {
    const selected = await findDexMemberEntry(
      reader,
      resolution.containerPath,
      resolution.member,
      resolution.signal,
    );
    if (!selected.ok) return err(selected.error);
    const staged = await stageDexMember(reader, resolution, selected.value);
    const classified = await classifyStandaloneDex(
      staged.path,
      resolution.inputPath,
      resolution.hostArchitecture,
      resolution.signal,
    );
    if (!classified.ok) return err(classified.error);
    return ok({
      path: staged.path,
      sourcePath: resolution.sourcePath,
      sha256: staged.sha256,
      kind: "executable",
      format: "dex",
      architecture: "dalvik",
      availableArchitectures: ["dalvik"],
      dex: classified.value,
      containerSelection: {
        path: resolution.containerPath,
        sha256: resolution.containerSha256,
        member: resolution.member,
      },
    });
  } finally {
    await reader.close();
  }
};

/** Exact-name lookup across one enumeration with DEX-member context on miss. */
const findDexMemberEntry = async (
  reader: ZipArtifactReader,
  containerPath: string,
  member: string,
  signal?: AbortSignal,
): Promise<Result<ArtifactEntry, BinaryTargetError>> => {
  const members = new Set<string>();
  let found: ArtifactEntry | undefined;
  for await (const entry of reader.entries(signal)) {
    throwIfCancelled(signal);
    if (entry.kind !== "file") continue;
    if (entry.path.toLowerCase().endsWith(".dex")) members.add(entry.path);
    if (entry.path === member) found = entry;
  }
  if (found === undefined) {
    const listed = [...members].slice(0, MAX_LISTED_MEMBER_NAMES);
    const suffix =
      members.size > MAX_LISTED_MEMBER_NAMES
        ? `, and ${members.size - MAX_LISTED_MEMBER_NAMES} more`
        : "";
    return err(
      new BinaryTargetError(
        containerPath,
        `Container member ${JSON.stringify(member)} was not found; DEX members: ${listed.length === 0 ? "none" : `${listed.join(", ")}${suffix}`}.`,
      ),
    );
  }
  if (found.encrypted === true)
    return err(
      new BinaryTargetError(
        containerPath,
        `Container member ${JSON.stringify(member)} is encrypted and cannot be read.`,
      ),
    );
  return ok(found);
};

export interface StagedDexMember {
  /** Absolute path of the reused or freshly staged DEX file. */
  readonly path: string;
  /** SHA-256 of the member bytes, verified against the named entry. */
  readonly sha256: string;
}

const stagingRootFor = (
  containerPath: string,
  stagingDir: string | undefined,
): string =>
  stagingDir ??
  join(
    dirname(containerPath),
    `${basename(containerPath).slice(
      0,
      basename(containerPath).length - extname(containerPath).length,
    )}-extracted`,
  );

/**
 * Stream the member into a temporary staging file under the declared entry
 * size, hash it, then atomically reuse an equally digested staged file or
 * replace it. Staged bytes are never deleted by resolution.
 */
const stageDexMember = async (
  reader: ZipArtifactReader,
  resolution: ContainerDexResolution,
  entry: ArtifactEntry,
): Promise<StagedDexMember> => {
  const stagingRoot = stagingRootFor(
    resolution.containerPath,
    resolution.stagingDir,
  );
  const stagedPath = join(stagingRoot, basename(entry.path));
  const temporary = `${stagedPath}.${randomUUID()}.partial`;
  const declared = entry.declaredSize;
  if (
    typeof declared !== "number" ||
    !Number.isSafeInteger(declared) ||
    declared <= 0
  )
    throw new BinaryTargetError(
      resolution.containerPath,
      `Container member ${JSON.stringify(entry.path)} has an unusable declared size.`,
    );
  throwIfCancelled(resolution.signal);
  await mkdir(stagingRoot, { recursive: true });
  let streamed;
  try {
    streamed = await streamStagingFile(
      reader,
      entry,
      temporary,
      declared,
      resolution.containerPath,
      resolution.signal,
    );
  } catch (cause) {
    // A failed staging attempt leaves no partial bytes for later reuse.
    await rm(temporary, { force: true });
    throw cause;
  }
  const { sha256 } = streamed;
  const reused = await digestStagedFile(stagedPath);
  if (reused === sha256) {
    await rm(temporary, { force: true });
    return { path: stagedPath, sha256 };
  }
  await renameStagedFile(temporary, stagedPath);
  return { path: stagedPath, sha256 };
};

const streamStagingFile = async (
  reader: ZipArtifactReader,
  entry: ArtifactEntry,
  temporary: string,
  declared: number,
  containerPath: string,
  signal?: AbortSignal,
): Promise<{ readonly sha256: string }> => {
  const hash = createHash("sha256");
  const source = await reader.open(entry, signal);
  const output = await open(temporary, "w", 0o600);
  let total = 0;
  try {
    for await (const chunk of source) {
      throwIfCancelled(signal);
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.length;
      if (total > declared)
        throw new BinaryTargetError(
          containerPath,
          `Container member ${JSON.stringify(entry.path)} grew past its declared ${declared} bytes while transmission was staged.`,
        );
      hash.update(bytes);
      await output.write(bytes);
    }
    if (total !== declared)
      throw new BinaryTargetError(
        containerPath,
        `Container member ${JSON.stringify(entry.path)} staged ${total} bytes, not its declared ${declared}.`,
      );
  } finally {
    await output.close().catch(() => undefined);
  }
  return { sha256: hash.digest("hex") };
};

const renameStagedFile = async (
  temporary: string,
  stagedPath: string,
): Promise<void> => {
  try {
    await rename(temporary, stagedPath);
    return;
  } catch {
    // Windows cannot rename over an existing file; replace after removal.
    await rm(stagedPath, { force: true });
  }
  await rename(temporary, stagedPath);
};

/** Stream-digest a previously staged file, or null the stage is absent. */
const digestStagedFile = async (path: string): Promise<string | null> => {
  let handle: FileHandle;
  try {
    handle = await open(path, "r");
  } catch {
    return null;
  }
  const hash = createHash("sha256");
  try {
    const chunk = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const observed = await handle.read(chunk, 0, chunk.length, null);
      if (observed.bytesRead === 0) break;
      hash.update(chunk.subarray(0, observed.bytesRead));
    }
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
};

/** Staged members must parse as standalone DEX before providers see them. */
const classifyStandaloneDex = async (
  stagedPath: string,
  inputPath: string,
  hostArchitecture: NodeJS.Architecture,
  signal?: AbortSignal,
): Promise<
  Result<
    Extract<BinaryTarget, { format: "dex" }>["dex"],
    BinaryTargetError | AnalysisCancelledError
  >
> => {
  try {
    throwIfCancelled(signal);
    const admitted = await openRegularFile(stagedPath, {
      symlinks: "reject",
    });
    try {
      const metadata = await admitted.stat();
      const prefix = Buffer.alloc(4096);
      const probe = await admitted.read(prefix, 0, prefix.length, 0);
      const parsed = parseExecutableHeader(
        prefix.subarray(0, probe.bytesRead),
        hostArchitecture,
        metadata.size,
      );
      if (!parsed.ok)
        return err(
          new BinaryTargetError(
            inputPath,
            `Selected container member is not a supported DEX image: ${parsed.error}`,
          ),
        );
      if (parsed.value.format !== "dex")
        return err(
          new BinaryTargetError(
            inputPath,
            `Selected container member is a ${parsed.value.format} image, not a DEX; only .dex entries are admissible inside containers.`,
          ),
        );
      return ok(parsed.value.dex);
    } finally {
      await admitted.close();
    }
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) return err(cause);
    if (cause instanceof BinaryTargetError) return err(cause);
    if (!(cause instanceof Error)) throw cause;
    const code: unknown = Reflect.get(cause, "code");
    if (typeof code !== "string") throw cause;
    return err(
      new BinaryTargetError(
        inputPath,
        `Staged container member could not be read (${code}): ${cause.message}`,
        { cause },
      ),
    );
  }
};
