import { createHash } from "node:crypto";

import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import { streamChunkToBuffer } from "../artifacts/StreamBytes.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import { jvmBinaryNameSchema } from "../domain/jvm/jvmArtifact.js";
import { CFR_LIMITS } from "./CfrRelease.js";
import { readJvmClassHeader, type JvmClassHeader } from "./JvmClassFile.js";

/** One class entry of a JAR, named by its entry path. */
export interface JvmJarClass {
  readonly name: string;
  readonly entry: string;
  readonly bytes: number | null;
}

/** Bytes and header of one class read back from the private JAR copy. */
export interface JvmClassObservation {
  readonly sha256: string;
  readonly header: JvmClassHeader;
}

/**
 * Class entries of a JAR snapshot. Multi-release copies under META-INF and
 * module/package descriptors are not addressable classes and are omitted.
 */
export const listJarClasses = async (
  path: string,
  signal?: AbortSignal,
): Promise<{
  readonly classes: JvmJarClass[];
  readonly read: (
    entry: string,
    signal?: AbortSignal,
  ) => Promise<JvmClassObservation>;
  readonly close: () => Promise<void>;
}> => {
  // Classes are addressed by entry path, and shaded dependency archives often
  // repeat license files or even class records; keep the first record.
  const reader = new ZipArtifactReader(
    path,
    "zip",
    undefined,
    undefined,
    "first",
  );
  const entries = new Map<string, ArtifactEntry>();
  const classes: JvmJarClass[] = [];
  try {
    for await (const entry of reader.entries(signal)) {
      if (
        entry.kind !== "file" ||
        !entry.path.endsWith(".class") ||
        entry.path.startsWith("META-INF/")
      )
        continue;
      const name = entry.path.slice(0, -".class".length).replaceAll("/", ".");
      if (!jvmBinaryNameSchema.safeParse(name).success) continue;
      entries.set(entry.path, entry);
      classes.push({ name, entry: entry.path, bytes: entry.declaredSize });
    }
  } catch (cause: unknown) {
    await reader.close();
    throw cause;
  }
  return {
    classes,
    read: async (path, readSignal) => {
      const entry = entries.get(path);
      if (entry === undefined)
        throw new TypeError(`JAR inventory has no entry ${path}`);
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of await reader.open(entry, readSignal)) {
        const bytes = streamChunkToBuffer(chunk);
        total += bytes.length;
        if (total > CFR_LIMITS.inputBytes)
          throw new RangeError(`JAR entry ${path} exceeds the input budget`);
        chunks.push(bytes);
      }
      const bytes = Buffer.concat(chunks);
      return {
        sha256: createHash("sha256").update(bytes).digest("hex"),
        header: readJvmClassHeader(bytes),
      };
    },
    close: () => reader.close(),
  };
};

/**
 * The top-level class whose source CFR emits for a binary name: CFR writes
 * nested classes into their outermost class, so `$` suffixes are removed
 * while the shorter name is itself a class in the inventory.
 */
export const topLevelClass = (
  name: string,
  inventory: ReadonlySet<string>,
): string => {
  let current = name;
  for (
    let separator = current.lastIndexOf("$");
    separator > 0;
    separator = current.lastIndexOf("$")
  ) {
    const outer = current.slice(0, separator);
    if (!inventory.has(outer)) break;
    current = outer;
  }
  return current;
};
