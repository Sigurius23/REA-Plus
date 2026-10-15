import { createHash } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

import { createProviderTargetSnapshot } from "../../../src/process/ProviderTargetSnapshot.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("provider target snapshot", () => {
  it("uses the selected installation platform instead of the ambient host", async () => {
    const root = await createTestTempDirectory("rea-snapshot-platform-");
    roots.push(root);
    const source = join(root, "source.exe");
    const bytes = Buffer.from("platform fixture");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(source, bytes);
    const snapshot = await createProviderTargetSnapshot(source, root, sha256, {
      providerName: "Ghidra",
      platform: "linux",
    });
    expect(snapshot.admission).toBeUndefined();
    await expect(readFile(snapshot.path)).resolves.toEqual(bytes);
    await expect(
      createProviderTargetSnapshot(source, root, sha256, {
        providerName: "Ghidra",
        platform: "linux",
      }),
    ).rejects.toMatchObject({ code: "EEXIST" });
    await expect(readFile(snapshot.path)).resolves.toEqual(bytes);
    await expect(
      createProviderTargetSnapshot(source, root, sha256, {
        providerName: "Ghidra",
        platform: "win32",
      }),
    ).rejects.toThrow(/No native private runtime owns/u);
  });

  it("names the admitting provider and removes a copy whose bytes changed", async () => {
    const root = await createTestTempDirectory("rea-snapshot-digest-");
    roots.push(root);
    const source = join(root, "source.elf");
    await writeFile(source, "changed after parsing");
    const parsedSha256 = createHash("sha256")
      .update("parsed bytes")
      .digest("hex");
    await expect(
      createProviderTargetSnapshot(source, root, parsedSha256, {
        providerName: "radare2",
        platform: "linux",
      }),
    ).rejects.toMatchObject({
      _tag: "AnalysisArtifactChangedError",
      reason: expect.stringMatching(
        /^radare2 target snapshot digest mismatch: expected [a-f0-9]{64}/u,
      ),
    });
    await expect(
      readFile(join(root, `target-${parsedSha256.slice(0, 12)}.elf`)),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
