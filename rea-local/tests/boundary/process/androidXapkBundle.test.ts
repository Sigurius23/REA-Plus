import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { describe, expect, it } from "vitest";

import { ZipArtifactReader } from "../../../src/artifacts/ZipArtifactReader.js";
import { composeAndroidXapkBundle } from "../../../src/android/AndroidXapkBundle.js";
import { AnalysisCapabilityUnavailableError } from "../../../src/domain/analysisErrorCore.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const DEX_BYTES = Uint8Array.from([
  0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0,
]);
const MANIFEST_BYTES = Uint8Array.from([3, 0, 8, 0]);
const RESOURCE_BYTES = Uint8Array.from([0x72, 0x65, 0x73, 0x73]);
const ELF_BYTES = Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);

const buildApk = async (
  entries: readonly (readonly [name: string, bytes: Uint8Array])[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const [name, bytes] of entries)
    await writer.add(name, new Uint8ArrayReader(bytes));
  return writer.close();
};

const buildXapk = async (
  entries: readonly (readonly [name: string, bytes: Uint8Array])[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const [name, bytes] of entries)
    await writer.add(name, new Uint8ArrayReader(bytes));
  const bytes = await writer.close();
  return bytes;
};

const writeFixture = async (
  root: string,
  name: string,
  bytes: Uint8Array,
): Promise<string> => {
  const path = join(root, name);
  await writeFile(path, bytes);
  return path;
};

const entryBytes = async (
  path: string,
  name: string,
): Promise<Uint8Array | undefined> => {
  const reader = new ZipArtifactReader(path, "apk", undefined, undefined);
  try {
    for await (const entry of reader.entries()) {
      if (entry.path !== name) continue;
      const source = await reader.open(entry);
      const chunks: Buffer[] = [];
      for await (const chunk of source)
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return Buffer.concat(chunks);
    }
    return undefined;
  } finally {
    await reader.close();
  }
};

describe("XAPK bundle admission", () => {
  it("composes one stored-entry APK with base plus split DEX entries", async () => {
    const root = await createTestTempDirectory("rea-xapk-");
    const base = await buildApk([
      ["AndroidManifest.xml", MANIFEST_BYTES],
      ["resources.arsc", RESOURCE_BYTES],
      ["classes.dex", DEX_BYTES],
      ["lib/arm64-v8a/libbase.so", ELF_BYTES],
    ]);
    const split = await buildApk([
      ["classes.dex", Uint8Array.from([1, 2, 3])],
      ["classes2.dex", Uint8Array.from([4, 5, 6, 7])],
      ["lib/arm64-v8a/libsplit.so", ELF_BYTES],
    ]);
    const container = await buildXapk([
      ["manifest.json", new TextEncoder().encode("{}")],
      ["base.apk", base],
      ["split_config.arm64_v8a.apk", split],
    ]);
    const containerPath = await writeFixture(root, "Bundle.xapk", container);
    const runtimeRoot = join(root, "runtime");
    await mkdir(runtimeRoot);

    const snapshot = await composeAndroidXapkBundle(
      {
        path: containerPath,
        sha256: createHash("sha256").update(container).digest("hex"),
      },
      runtimeRoot,
      "inspect_android_package",
      new AbortController().signal,
    );

    expect(snapshot.members).toEqual([
      "base.apk",
      "split_config.arm64_v8a.apk",
    ]);
    expect(snapshot.mergedMembers).toEqual([
      "base.apk",
      "split_config.arm64_v8a.apk",
    ]);
    expect(snapshot.limitations.join(" ")).toContain("split_config.arm64_v8a");
    expect(await existsOnDisk(snapshot.path)).toBe(true);
    const observed = await readFile(snapshot.path);
    expect(snapshot.sha256).toBe(
      createHash("sha256").update(observed).digest("hex"),
    );

    // The composed image keeps base entries verbatim, adds split DEX entries,
    // and only lets colliding split names through under splits/<member>/.
    expect(await entryBytes(snapshot.path, "AndroidManifest.xml")).toEqual(
      Buffer.from(MANIFEST_BYTES),
    );
    expect(await entryBytes(snapshot.path, "resources.arsc")).toEqual(
      Buffer.from(RESOURCE_BYTES),
    );
    expect(await entryBytes(snapshot.path, "classes.dex")).toEqual(
      Buffer.from(DEX_BYTES),
    );
    expect(await entryBytes(snapshot.path, "classes2.dex")).toEqual(
      Buffer.from([4, 5, 6, 7]),
    );
    expect(
      await entryBytes(
        snapshot.path,
        "splits/split_config.arm64_v8a/classes.dex",
      ),
    ).toEqual(Buffer.from([1, 2, 3]));
    expect(await entryBytes(snapshot.path, "lib/arm64-v8a/libbase.so")).toEqual(
      Buffer.from(ELF_BYTES),
    );
    // Split resources and native libraries stay out of the merged image.
    expect(
      await entryBytes(snapshot.path, "lib/arm64-v8a/libsplit.so"),
    ).toBeUndefined();

    // Staged member APKs are transient admission state inside the runtime root.
    expect(await readdir(runtimeRoot)).toEqual(["bundle.apk"]);

    await rm(snapshot.path, { force: true });
  });

  it("refuses a XAPK without a readable top-level base module", async () => {
    const root = await createTestTempDirectory("rea-xapk-missing-base-");
    const split = await buildApk([["classes2.dex", DEX_BYTES]]);
    const container = await buildXapk([
      ["manifest.json", new TextEncoder().encode("{}")],
      ["splits/base.apk", split],
    ]);
    const containerPath = await writeFixture(root, "Bundle.xapk", container);

    await expect(
      composeAndroidXapkBundle(
        {
          path: containerPath,
          sha256: createHash("sha256").update(container).digest("hex"),
        },
        join(root, "runtime"),
        "inspect_android_package",
        new AbortController().signal,
      ),
    ).rejects.toThrow(AnalysisCapabilityUnavailableError);
  });

  it("refuses a ZIP package without the XAPK manifest", async () => {
    const root = await createTestTempDirectory("rea-xapk-manifest-");
    const container = await buildXapk([
      ["metadata.json", new TextEncoder().encode("{}")],
    ]);
    const containerPath = await writeFixture(root, "Bundle.xapk", container);

    await expect(
      composeAndroidXapkBundle(
        {
          path: containerPath,
          sha256: createHash("sha256").update(container).digest("hex"),
        },
        join(root, "runtime"),
        "inspect_android_package",
        new AbortController().signal,
      ),
    ).rejects.toThrow(/manifest\.json/u);
  });
});

const existsOnDisk = async (path: string): Promise<boolean> => {
  const bytes = await readFile(path).catch(() => undefined);
  return bytes !== undefined && bytes.length > 0;
};
