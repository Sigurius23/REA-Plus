import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  rm,
  rmdir,
  type FileHandle,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Readable } from "node:stream";

import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import type { AndroidOperation } from "../domain/android/androidAnalysis.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";

/** Top-level XAPK manifest describing the packaged APK members. */
const XAPK_MANIFEST_ENTRY = "manifest.json";
/** Base APK name every XAPK must carry next to the manifest. */
const XAPK_BASE_APK_ENTRY = "base.apk";
/** Smallest plausible ZIP file entry; smaller "APK" members are packaging debris. */
const MINIMUM_APK_MEMBER_BYTES = 4;
/** Upper bound on the composed analysis image, mirroring the 4 GiB ZIP ceiling. */
const MAXIMUM_COMPOSED_BYTES = 4 * 1024 * 1024 * 1024 - 1;
/** ZIP32 stores entry counts in 16 bits; jadx never needs more than that. */
const MAXIMUM_COMPOSED_ENTRIES = 0xffff;
/** How many ignored member names one admission refusal lists before truncating. */
const MAXIMUM_LISTED_MEMBERS = 5;

/**
 * Composed analysis image plus the admission facts that connect it to its XAPK
 * container. `members` names every accepted APK member with the base module
 * first, `mergedMembers` the ones whose entries actually reached the image and
 * `limitations` the honest scope notes attached to the provider evidence.
 */
export interface AndroidXapkBundleSnapshot {
  readonly path: string;
  readonly sha256: string;
  readonly members: readonly string[];
  readonly mergedMembers: readonly string[];
  readonly limitations: readonly string[];
}

interface XapkMember {
  readonly entry: ArtifactEntry;
  /** Member name inside the composed image; the base module keeps base.apk. */
  readonly destination: string;
}

/**
 * Compose one merged analysis APK for jadx from an admitted XAPK container.
 *
 * jadx consumes standalone APK files only, so admission builds the image the
 * engine will actually load: each APK member is staged out of the container as
 * a regular file, opened as a nested ZIP, and its Java entries (`*.dex`) are
 * copied into one stored-entry image. The base module contributes every file
 * entry, so manifest, resources and native libraries stay mapped; split
 * modules only contribute code entries, renamed under
 * `splits/<member>/<name>` when their declared name would collide. Split
 * resources, native libraries and member signatures are deliberately not
 * merged and are reported through the returned limitations; the composed
 * image is an analysis artifact, not the signed install package.
 *
 * Members are staged per merge step so composition memory stays constant and
 * a failed admission leaves no composed image for later callers to trust.
 */
export const composeAndroidXapkBundle = async (
  target: Pick<BinaryTarget, "path" | "sha256">,
  root: string,
  operation: AndroidOperation,
  signal: AbortSignal,
): Promise<AndroidXapkBundleSnapshot> => {
  const reader = new ZipArtifactReader(
    target.path,
    "xapk",
    undefined,
    undefined,
  );
  try {
    const members = await planXapkComposition(
      reader,
      target.path,
      operation,
      signal,
    );
    signal.throwIfAborted();
    return await composeMergedImage(
      reader,
      target.path,
      members,
      root,
      operation,
      signal,
    );
  } catch (cause: unknown) {
    throw await translatedBundleFailure(cause, target.path, operation, signal);
  } finally {
    await reader.close().catch(() => undefined);
  }
};

/** Require an admitted XAPK shape before any composed bytes are written. */
const planXapkComposition = async (
  reader: ZipArtifactReader,
  containerPath: string,
  operation: AndroidOperation,
  signal: AbortSignal,
): Promise<readonly XapkMember[]> => {
  let hasManifest = false;
  const ignored: string[] = [];
  const members: XapkMember[] = [];
  for await (const entry of reader.entries(signal)) {
    signal.throwIfAborted();
    if (entry.kind !== "file") continue;
    if (entry.path === XAPK_MANIFEST_ENTRY) {
      hasManifest = true;
      continue;
    }
    const member = xapkMemberFor(entry, ignored);
    if (member !== undefined) members.push(member);
  }
  signal.throwIfAborted();
  enforceDeclaredContainerSize(members, containerPath, operation);
  verifyAdmittedMembership(
    members,
    hasManifest,
    ignored,
    containerPath,
    operation,
  );
  return [...members].sort(compareMemberOrder);
};

/**
 * Map one container entry to a composed-image member, or explain why it is
 * ignored. Only APK files adjacent to the manifest are admitted; nested trees
 * inside the container stay out of jadx's view and are listed as ignored so
 * callers can repackage a mis-shaped container.
 */
const xapkMemberFor = (
  entry: ArtifactEntry,
  ignored: string[],
): XapkMember | undefined => {
  const lower = entry.path.toLowerCase();
  if (!lower.endsWith(".apk")) return undefined;
  if (entry.encrypted) {
    ignored.push(`${entry.path} (encrypted)`);
    return undefined;
  }
  if (entry.path.includes("/")) {
    ignored.push(`${entry.path} (nested below the manifest)`);
    return undefined;
  }
  if ((entry.declaredSize ?? 0) < MINIMUM_APK_MEMBER_BYTES) {
    ignored.push(`${entry.path} (too small to hold APK bytes)`);
    return undefined;
  }
  return { entry, destination: basename(entry.path).toLowerCase() };
};

/** Capacity refusal operates on declared sizes before any bytes are read. */
const enforceDeclaredContainerSize = (
  members: readonly XapkMember[],
  containerPath: string,
  operation: AndroidOperation,
): void => {
  const declared = members.reduce(
    (total, member) => total + (member.entry.declaredSize ?? 0),
    0,
  );
  if (declared <= MAXIMUM_COMPOSED_BYTES) return;
  throw new AnalysisInputError(operation, undefined, [
    {
      path: ["path"],
      reason: "invalid_value",
      message: `XAPK members of ${containerPath} declare a combined ${declared} bytes, beyond the ${MAXIMUM_COMPOSED_BYTES}-byte composed image admission cap.`,
    },
  ]);
};

const verifyAdmittedMembership = (
  members: readonly XapkMember[],
  hasManifest: boolean,
  ignored: readonly string[],
  containerPath: string,
  operation: AndroidOperation,
): void => {
  if (!hasManifest)
    throw unsupportedXapk(
      operation,
      containerPath,
      `XAPK containers must include a top-level ${JSON.stringify(XAPK_MANIFEST_ENTRY)} describing their APK members.`,
    );
  if (!members.some(({ destination }) => destination === XAPK_BASE_APK_ENTRY))
    throw unsupportedXapk(
      operation,
      containerPath,
      `XAPK containers must carry one readable top-level ${JSON.stringify(XAPK_BASE_APK_ENTRY)} as the base module${describeIgnored(ignored)}.`,
    );
};

const describeIgnored = (ignored: readonly string[]): string => {
  if (ignored.length === 0) return "";
  const listed = ignored.slice(0, MAXIMUM_LISTED_MEMBERS).join(", ");
  const rest = ignored.length - MAXIMUM_LISTED_MEMBERS;
  return `; ignored container members: ${listed}${rest > 0 ? `, and ${rest} more` : ""}`;
};

/** The base module sorts ahead so manifest/resources map before split code. */
const compareMemberOrder = (left: XapkMember, right: XapkMember): number => {
  if (left.destination === right.destination) return 0;
  if (left.destination === XAPK_BASE_APK_ENTRY) return -1;
  if (right.destination === XAPK_BASE_APK_ENTRY) return 1;
  return left.destination < right.destination
    ? -1
    : left.destination > right.destination
      ? 1
      : 0;
};

const basename = (path: string): string => {
  const separator = path.lastIndexOf("/");
  return separator === -1 ? path : path.slice(separator + 1);
};

const composeMergedImage = async (
  container: ZipArtifactReader,
  containerPath: string,
  members: readonly XapkMember[],
  root: string,
  operation: AndroidOperation,
  signal: AbortSignal,
): Promise<AndroidXapkBundleSnapshot> => {
  const destination = join(root, "bundle.apk");
  const writer = await ComposedImageWriter.create(destination);
  const mergedMembers: string[] = [];
  const composedNames = new Set<string>();
  let dexEntryCount = 0;
  try {
    for (const index of members.keys()) {
      signal.throwIfAborted();
      const member = members[index]!;
      const stagedPath = await stageMemberApk(
        container,
        containerPath,
        member,
        join(root, "source", `${index}.apk`),
        operation,
        signal,
      );
      const memberReader = new ZipArtifactReader(
        stagedPath,
        "apk",
        undefined,
        undefined,
      );
      try {
        const merged = await copyMemberEntries(
          memberReader,
          member.destination,
          composedNames,
          writer,
          containerPath,
          signal,
        );
        if (merged || member.destination === XAPK_BASE_APK_ENTRY)
          mergedMembers.push(member.destination);
      } finally {
        await memberReader.close().catch(() => undefined);
        await rm(stagedPath, { force: true }).catch(() => undefined);
      }
    }
    dexEntryCount = [...composedNames].filter((name) =>
      name.toLowerCase().endsWith(".dex"),
    ).length;
    if (dexEntryCount === 0)
      throw new AnalysisInputError(operation, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `XAPK members of ${containerPath} admit no Java entries; jadx reads only *.dex code entries.`,
        },
      ]);
    signal.throwIfAborted();
    const sha256 = await writer.finalize(signal);
    await chmod(destination, 0o400);
    // Staging only ever lives under source/ and only while members merge.
    await rmdir(join(root, "source")).catch(() => undefined);
    return {
      path: destination,
      sha256,
      members: members.map(({ destination: name }) => name),
      mergedMembers,
      limitations: composedImageLimitations(mergedMembers, dexEntryCount),
    };
  } catch (cause: unknown) {
    await writer.close().catch(() => undefined);
    // Failed admissions leave no composed image: the caller must never see a
    // half-merged bundle.apk that later requests could mistakenly trust.
    await rm(destination, { force: true }).catch(() => undefined);
    throw cause;
  }
};

/** Extract one member APK into an exclusively owned regular staging file. */
const stageMemberApk = async (
  container: ZipArtifactReader,
  containerPath: string,
  member: XapkMember,
  stagedPath: string,
  operation: AndroidOperation,
  signal: AbortSignal,
): Promise<string> => {
  const declared = member.entry.declaredSize;
  if (
    typeof declared !== "number" ||
    !Number.isSafeInteger(declared) ||
    declared <= 0
  )
    throw new AnalysisInputError(operation, undefined, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: `XAPK member ${JSON.stringify(member.entry.path)} has an unusable declared size.`,
      },
    ]);
  let source: Readable | undefined;
  let handle: FileHandle | undefined;
  let staged = 0;
  try {
    source = await container.open(member.entry, signal);
    await mkdir(dirname(stagedPath), { recursive: true });
    handle = await open(stagedPath, "wx", 0o600);
    for await (const chunk of source) {
      signal.throwIfAborted();
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      staged += bytes.length;
      if (staged > declared)
        throw memberIntegrityFailure(
          containerPath,
          member.destination,
          `grew past its declared ${declared} bytes while being staged`,
        );
      await handle.write(bytes, 0, bytes.length);
    }
    signal.throwIfAborted();
    if (staged !== declared)
      throw memberIntegrityFailure(
        containerPath,
        member.destination,
        `staged ${staged} bytes, not its declared ${declared}`,
      );
    return stagedPath;
  } catch (cause: unknown) {
    await rm(stagedPath, { force: true }).catch(() => undefined);
    throw cause;
  } finally {
    await handle?.close().catch(() => undefined);
    source?.destroy();
  }
};

/**
 * Copy the member's Java entries into the composed image. The base module
 * contributes every file entry; every other member contributes only `*.dex`
 * entries. Declared names are kept when unused, and colliding split entries
 * are renamed under `splits/<member>/` so jadx still decompiles them while
 * the runtime loader could never implicitly trust the alias.
 */
const copyMemberEntries = async (
  memberReader: ZipArtifactReader,
  memberName: string,
  composedNames: Set<string>,
  writer: ComposedImageWriter,
  containerPath: string,
  signal: AbortSignal,
): Promise<boolean> => {
  let merged = false;
  const declaredNames = new Set<string>();
  for await (const entry of memberReader.entries(signal)) {
    signal.throwIfAborted();
    if (entry.kind !== "file") continue;
    const declared = entry.path.replace(/^\/+/u, "");
    if (declared.length === 0) continue;
    const isDex = declared.toLowerCase().endsWith(".dex");
    if (memberName !== XAPK_BASE_APK_ENTRY && !isDex) continue;
    if (!isDex && !adoptedBaseEntry(declared)) continue;
    if (declaredNames.has(declared.toLowerCase()))
      throw memberIntegrityFailure(
        containerPath,
        memberName,
        `carries duplicate entry ${JSON.stringify(entry.path)}`,
      );
    declaredNames.add(declared.toLowerCase());
    if (entry.encrypted)
      throw unsupportedXapk(
        "inspect_android_package",
        containerPath,
        `Member ${JSON.stringify(memberName)} carries encrypted ${JSON.stringify(entry.path)}; encrypted payload entries cannot feed jadx.`,
      );
    const destination = uniqueEntryName(declared, composedNames, memberName);
    const declaredSize = entry.declaredSize;
    if (
      typeof declaredSize !== "number" ||
      !Number.isSafeInteger(declaredSize) ||
      declaredSize < 0
    )
      throw new AnalysisInputError("inspect_android_package", undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Member ${JSON.stringify(memberName)} entry ${JSON.stringify(entry.path)} has an unusable declared size.`,
        },
      ]);
    await writer.add(
      destination,
      () => memberReader.open(entry, signal),
      declaredSize,
      containerPath,
      memberName,
      signal,
    );
    composedNames.add(destination.toLowerCase());
    if (isDex) merged = true;
  }
  signal.throwIfAborted();
  return merged;
};

/**
 * Non-code base entries other than resources keep the composed image browsable
 * by jadx; directories are skipped because zip readers derive them from names.
 */
const adoptedBaseEntry = (declared: string): boolean =>
  !declared.endsWith("/") && declared.toLowerCase() !== XAPK_MANIFEST_ENTRY;

const uniqueEntryName = (
  declared: string,
  composedNames: ReadonlySet<string>,
  memberName: string,
): string => {
  const lower = declared.toLowerCase();
  if (!composedNames.has(lower)) return declared;
  const stem = memberName.replace(/\.apk$/u, "");
  return `splits/${stem}/${declared}`;
};

const composedImageLimitations = (
  mergedMembers: readonly string[],
  dexEntryCount: number,
): readonly string[] => {
  const splits = mergedMembers.filter((name) => name !== XAPK_BASE_APK_ENTRY);
  const scope =
    splits.length === 0
      ? "base.apk only"
      : `${mergedMembers.length} members (${mergedMembers.join(", ")})`;
  return [
    `Composed XAPK analysis merged JAVA code of ${scope} (${dexEntryCount} DEX entries) into one analysis image; split resources, native libraries and member signatures were not merged, and the image is not the signed install package.`,
  ];
};

const memberIntegrityFailure = (
  containerPath: string,
  memberName: string,
  reason: string,
  cause?: unknown,
): AnalysisInputError =>
  new AnalysisInputError("inspect_android_package", { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message: `Member ${JSON.stringify(memberName)} of ${containerPath} ${reason}.`,
    },
  ]);

/** Map reader/IO failures from container and member stages onto op surfaces. */
const translatedBundleFailure = async (
  cause: unknown,
  containerPath: string,
  operation: AndroidOperation,
  signal: AbortSignal,
): Promise<Error> => {
  if (signal.aborted && !(cause instanceof AnalysisError))
    return new AnalysisCancelledError(operation, { cause: cause as Error });
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "format")
      return unsupportedXapk(
        operation,
        containerPath,
        "The XAPK container is not a readable ZIP package.",
        cause,
      );
    if (cause.reason === "limit")
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `XAPK metadata at ${containerPath} exceeded the ZIP inspection budget.`,
        },
      ]);
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: `XAPK container at ${containerPath} could not be inspected: ${cause.message}`,
      },
    ]);
  }
  if (cause instanceof Error) return cause;
  return new Error(String(cause), { cause });
};

const unsupportedXapk = (
  operation: AndroidOperation,
  path: string,
  reason: string,
  cause?: unknown,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(
    "jadx",
    operation,
    `Selected ${path} is not analyzable. ${reason}`,
    cause === undefined ? undefined : { cause },
  );

/**
 * Minimal stored-entry ZIP writer for the merged analysis image.
 *
 * Each entry streams its (already decompressed) bytes into the image and gets
 * its local header's CRC-32 and size fields patched in place afterwards, so
 * memory stays constant regardless of member size. The central directory is
 * small and bounded, so it is buffered.
 */
class ComposedImageWriter {
  static async create(path: string): Promise<ComposedImageWriter> {
    const handle = await open(path, "wx", 0o600);
    return new ComposedImageWriter(path, handle);
  }

  #handle: FileHandle | undefined;
  #offset = 0;
  readonly #path: string;
  readonly #records: {
    readonly name: Buffer;
    readonly crc: number;
    readonly size: number;
    readonly offset: number;
  }[] = [];

  private constructor(path: string, handle: FileHandle) {
    this.#path = path;
    this.#handle = handle;
  }

  get byteSize(): number {
    return this.#offset;
  }

  /**
   * Copy one entry under `name` from the supplied opener. Declared size and
   * streamed size must agree, or the member lies to its reader and the merge
   * is refused, so a bounded admission can never outgrow the cap silently.
   */
  async add(
    name: string,
    openSource: () => Promise<Readable>,
    declaredSize: number,
    containerPath: string,
    memberName: string,
    signal: AbortSignal,
  ): Promise<void> {
    const handle = this.#handle;
    if (handle === undefined)
      throw new Error("Composed APK image writer already closed");
    if (this.#offset + declaredSize > MAXIMUM_COMPOSED_BYTES)
      throw unavailableComposedImage(
        containerPath,
        `Adding ${JSON.stringify(name)} of ${JSON.stringify(declaredSize)} bytes from ${JSON.stringify(memberName)} would pass the ${MAXIMUM_COMPOSED_BYTES}-byte composed image cap.`,
      );
    if (this.#records.length >= MAXIMUM_COMPOSED_ENTRIES)
      throw unavailableComposedImage(
        containerPath,
        `Adding ${JSON.stringify(name)} from ${JSON.stringify(memberName)} would pass the ${String(MAXIMUM_COMPOSED_ENTRIES)}-entry ZIP limit.`,
      );
    const encoded = Buffer.from(name, "utf8");
    if (encoded.length > 0xffff)
      throw unavailableComposedImage(
        containerPath,
        `Entry name ${JSON.stringify(name)} exceeds the ZIP name length limit.`,
      );
    const entryOffset = this.#offset;
    const header = Buffer.alloc(30 + encoded.length);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6); // Entry names are UTF-8 encoded.
    header.writeUInt16LE(0, 8); // Data is stored uncompressed.
    header.writeUInt16LE(0, 10);
    header.writeUInt16LE(0, 12);
    header.writeUInt32LE(0, 14);
    header.writeUInt32LE(0, 18);
    header.writeUInt32LE(0, 22);
    header.writeUInt16LE(encoded.length, 26);
    header.writeUInt16LE(0, 28);
    encoded.copy(header, 30);
    const source = await openSource();
    let crc = 0xffffffff;
    let size = 0;
    try {
      await this.#write(header, signal);
      for await (const chunk of source) {
        signal.throwIfAborted();
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += bytes.length;
        if (size > declaredSize)
          throw memberIntegrityFailure(
            containerPath,
            memberName,
            `entry ${JSON.stringify(name)} grew past its declared ${declaredSize} bytes while being composed`,
          );
        crc = updateCrc32(crc, bytes);
        await this.#write(bytes, signal);
      }
      signal.throwIfAborted();
      if (size !== declaredSize)
        throw memberIntegrityFailure(
          containerPath,
          memberName,
          `entry ${JSON.stringify(name)} streamed ${size} bytes, not its declared ${declaredSize}`,
        );
      const crcValue = (crc ^ 0xffffffff) >>> 0;
      this.#records.push({
        name: encoded,
        crc: crcValue,
        size,
        offset: entryOffset,
      });
      const patch = Buffer.alloc(12);
      patch.writeUInt32LE(crcValue, 0);
      patch.writeUInt32LE(size, 4);
      patch.writeUInt32LE(size, 8);
      await this.#patchAt(entryOffset + 14, patch, signal);
    } finally {
      source.destroy();
    }
  }

  /** Write the central directory, close the image, and digest its real bytes. */
  async finalize(signal: AbortSignal): Promise<string> {
    const handle = this.#handle;
    if (handle === undefined)
      throw new Error("Composed APK image writer already closed");
    const directoryStart = this.#offset;
    const directory = this.#centralDirectory();
    await this.#write(directory, signal);
    const record = Buffer.alloc(22);
    record.writeUInt32LE(0x06054b50, 0);
    record.writeUInt16LE(0, 4);
    record.writeUInt16LE(0, 6);
    record.writeUInt16LE(this.#records.length, 8);
    record.writeUInt16LE(this.#records.length, 10);
    record.writeUInt32LE(directory.length, 12);
    record.writeUInt32LE(directoryStart, 16);
    record.writeUInt16LE(0, 20);
    await this.#write(record, signal);
    await this.#closeHandle();
    // Local headers are patched in place after their bytes are written, so
    // the digest must be taken from the final on-disk image, not the stream.
    return digestComposedImage(this.#path);
  }

  /** Drop the handle so failed callers cannot write into a dead image. */
  async close(): Promise<void> {
    await this.#closeHandle();
  }

  async #closeHandle(): Promise<void> {
    const handle = this.#handle;
    this.#handle = undefined;
    if (handle !== undefined) await handle.close().catch(() => undefined);
  }

  #centralDirectory(): Buffer {
    const parts: Buffer[] = [];
    let total = 0;
    for (const entry of this.#records) {
      const record = Buffer.alloc(46 + entry.name.length);
      record.writeUInt32LE(0x02014b50, 0);
      record.writeUInt16LE(20, 4); // Version made by.
      record.writeUInt16LE(20, 6); // Version needed to extract.
      record.writeUInt16LE(0x0800, 8); // UTF-8 names.
      record.writeUInt16LE(0, 10); // Stored uncompressed.
      record.writeUInt16LE(0, 12); // File time and date default to DOS zero.
      record.writeUInt32LE(entry.crc, 16);
      record.writeUInt32LE(entry.size, 20); // Compressed size.
      record.writeUInt32LE(entry.size, 24); // Uncompressed size.
      record.writeUInt16LE(entry.name.length, 28); // File name length.
      record.writeUInt16LE(0, 30); // Extra field length.
      record.writeUInt16LE(0, 32); // Comment length.
      record.writeUInt16LE(0, 34); // Disk number where the entry starts.
      record.writeUInt16LE(0, 36); // Internal attributes.
      record.writeUInt32LE(0, 38); // External attributes.
      record.writeUInt32LE(entry.offset, 42); // Local header offset.
      entry.name.copy(record, 46);
      parts.push(record);
      total += record.length;
    }
    return Buffer.concat(parts, total);
  }

  async #patchAt(
    position: number,
    bytes: Buffer,
    signal: AbortSignal,
  ): Promise<void> {
    signal.throwIfAborted();
    const handle = this.#handle;
    if (handle === undefined)
      throw new Error("Composed APK image writer already closed");
    const written = await handle.write(bytes, 0, bytes.length, position);
    if (written.bytesWritten !== bytes.length)
      throw new Error("Composed APK image patch wrote short");
  }

  async #write(bytes: Buffer, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    const handle = this.#handle;
    if (handle === undefined)
      throw new Error("Composed APK image writer already closed");
    const written = await handle.write(bytes, 0, bytes.length, this.#offset);
    if (written.bytesWritten !== bytes.length)
      throw new Error("Composed APK image write was short");
    this.#offset += written.bytesWritten;
  }
}

const digestComposedImage = async (path: string): Promise<string> => {
  const handle = await open(path, "r");
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

const unavailableComposedImage = (
  path: string,
  reason: string,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(
    "jadx",
    "inspect_android_package",
    `Composed analysis image for ${path} was refused. ${reason}`,
  );

const CRC_TABLE: readonly number[] = Array.from(
  { length: 256 },
  (_: unknown, index: number): number => {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1)
      value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    return value >>> 0;
  },
);

const updateCrc32 = (seed: number, bytes: Buffer): number => {
  let crc = seed;
  for (let index = 0; index < bytes.length; index += 1)
    crc = CRC_TABLE[(crc ^ bytes[index]!) & 0xff]! ^ (crc >>> 8);
  return crc;
};
