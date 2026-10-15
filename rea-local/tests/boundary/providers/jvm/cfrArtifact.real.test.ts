import { execFileSync } from "node:child_process";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { JvmArtifactService } from "../../../../src/application/jvm/JvmArtifactService.js";
import { PrivateRuntimeRoot } from "../../../../src/process/PrivateRuntimeRoot.js";
import { CfrArtifactProvider } from "../../../../src/jvm/CfrArtifactProvider.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const configured = process.env.REA_VERIFY_CFR_JAR;
const CFR =
  configured === undefined || configured.length === 0 ? undefined : configured;
const javaTool = (tool: string) =>
  process.env.JAVA_HOME === undefined
    ? tool
    : join(process.env.JAVA_HOME, "bin", tool);
const hasJdk = (() => {
  try {
    execFileSync(javaTool("javac"), ["-version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const SOURCES: Readonly<Record<string, string>> = {
  "com/example/mod/LicenseCheck.java": `package com.example.mod;

import java.util.function.IntUnaryOperator;

public final class LicenseCheck {
    private static final String KEY = "SECRET-KEY-42";

    public static boolean verify(String candidate) {
        if (candidate == null) return false;
        IntUnaryOperator mix = x -> x * 31 + 7;
        int sum = 0;
        for (char c : candidate.toCharArray()) sum = mix.applyAsInt(sum + c);
        return KEY.equals(candidate) || sum == 0x5eed;
    }

    static final class Cache {
        int hits;
        void hit() { hits++; }
    }
}
`,
  "com/example/mod/Main.java": `package com.example.mod;

public class Main {
    public static void main(String[] args) {
        System.out.println(LicenseCheck.verify(args.length > 0 ? args[0] : ""));
    }
}
`,
};

/** Compile the sources with javac --release 17 and package them with jar. */
const buildArtifacts = async (root: string) => {
  const sources = join(root, "src");
  const classes = join(root, "classes");
  for (const [path, text] of Object.entries(SOURCES)) {
    await mkdir(join(sources, path, ".."), { recursive: true });
    await writeFile(join(sources, path), text);
  }
  execFileSync(
    javaTool("javac"),
    [
      "--release",
      "17",
      "-d",
      classes,
      ...Object.keys(SOURCES).map((path) => join(sources, path)),
    ],
    { stdio: "pipe" },
  );
  const jar = join(root, "mod.jar");
  execFileSync(javaTool("jar"), ["cf", jar, "-C", classes, "com"], {
    stdio: "pipe",
  });
  return {
    jar,
    classFile: join(classes, "com/example/mod/LicenseCheck.class"),
  };
};

describe.skipIf(CFR === undefined || !hasJdk)(
  "real CFR 0.152 lane (set REA_VERIFY_CFR_JAR; needs javac and jar)",
  () => {
    let root = "";
    let runtimeParent = "";
    let artifacts: Awaited<ReturnType<typeof buildArtifacts>>;
    let service: JvmArtifactService;
    beforeAll(async () => {
      root = (await createTestWorkspace("rea-cfr-real-")).root;
      runtimeParent = join(root, "runtime");
      await mkdir(runtimeParent);
      artifacts = await buildArtifacts(root);
      service = new JvmArtifactService(
        new CfrArtifactProvider(
          { ...process.env, REA_CFR_JAR: CFR },
          undefined,
          () => PrivateRuntimeRoot.create({ parent: runtimeParent }),
        ),
      );
    });
    afterAll(async () => {
      await service.close();
      await expect(readdir(runtimeParent)).resolves.toEqual([]);
      await removeTestWorkspace(root);
    });

    it("lists a JAR without decompiling until classes are named", async () => {
      const listed = await service.inspect({ path: artifacts.jar });
      if (!listed.ok) throw listed.error;
      expect(listed.value.normalized_result).toMatchObject({
        artifact: { path: artifacts.jar, kind: "jar" },
        classes: expect.arrayContaining([
          {
            name: "com.example.mod.LicenseCheck$Cache",
            entry: "com/example/mod/LicenseCheck$Cache.class",
            bytes: expect.any(Number),
          },
          expect.objectContaining({ name: "com.example.mod.Main" }),
        ]),
        decompiled: [],
        tool_profile: { decompiler: "CFR", release: "0.152", arguments: [] },
      });
      expect(JSON.stringify(listed.value)).not.toContain("Picked up");
    });

    it("decompiles selected classes and folds nested classes into their outer source", async () => {
      const result = await service.inspect({
        path: artifacts.jar,
        classes: ["com.example.mod.LicenseCheck$Cache", "com.example.mod.Main"],
      });
      if (!result.ok) throw result.error;
      const decompiled = (
        result.value.normalized_result as {
          decompiled: { top_level_class: string; text: string }[];
        }
      ).decompiled;
      expect(result.value.normalized_result).toMatchObject({
        decompiled: [
          {
            top_level_class: "com.example.mod.LicenseCheck",
            requested: ["com.example.mod.LicenseCheck$Cache"],
            class_version: { major: 61, minor: 0, java_release: 17 },
            source_path: "com/example/mod/LicenseCheck.java",
            representation: "cfr-decompiled-java",
            cfr_reported_failures: false,
          },
          {
            top_level_class: "com.example.mod.Main",
            source_path: "com/example/mod/Main.java",
          },
        ],
      });
      expect(decompiled[0]?.text).toContain("Decompiled with CFR 0.152.");
      expect(decompiled[0]?.text).toContain('KEY = "SECRET-KEY-42"');
      expect(decompiled[0]?.text).toContain("static final class Cache");
      expect(decompiled[1]?.text).toContain("LicenseCheck.verify(");
    });

    it("always decompiles a standalone class file", async () => {
      const result = await service.inspect({ path: artifacts.classFile });
      if (!result.ok) throw result.error;
      expect(result.value.normalized_result).toMatchObject({
        artifact: { kind: "class" },
        classes: [{ name: "com.example.mod.LicenseCheck", entry: null }],
        decompiled: [{ top_level_class: "com.example.mod.LicenseCheck" }],
      });
    });

    it("rejects unknown classes and non-JVM files before decompiling", async () => {
      expect(
        await service.inspect({
          path: artifacts.jar,
          classes: ["com.example.mod.Missing"],
        }),
      ).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [{ path: ["classes"], reason: "invalid_value" }],
        },
      });
      const text = join(root, "notes.txt");
      await writeFile(text, "not bytecode");
      expect(await service.inspect({ path: text })).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
    });
  },
);

describe("CFR configuration", () => {
  it("reports an unconfigured decompiler as unavailable", async () => {
    const workspace = await createTestWorkspace("rea-cfr-unset-");
    try {
      const path = join(workspace.root, "Empty.class");
      await writeFile(path, Buffer.from("cafebabe", "hex"));
      const unset = new JvmArtifactService(new CfrArtifactProvider({}));
      expect(await unset.inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisCapabilityUnavailableError",
          providerId: "cfr-jvm-decompiler",
          userMessage: expect.stringContaining("REA_CFR_JAR"),
        },
      });
    } finally {
      await removeTestWorkspace(workspace.root);
    }
  });
});
