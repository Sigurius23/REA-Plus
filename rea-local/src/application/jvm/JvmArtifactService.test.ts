import { createHash } from "node:crypto";

import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { JvmArtifact } from "../../domain/jvm/jvmArtifact.js";
import { ok } from "../../domain/result.js";
import { JvmArtifactService } from "./JvmArtifactService.js";

const PATH = "/artifacts/mod.jar";
const text = "package com.example.mod;\n\npublic class Main {\n}\n";
const report = (): JvmArtifact => ({
  artifact: { path: PATH, sha256: "a".repeat(64), bytes: 10, kind: "jar" },
  classes: [
    {
      name: "com.example.mod.Main",
      entry: "com/example/mod/Main.class",
      bytes: 4,
    },
  ],
  decompiled: [
    {
      top_level_class: "com.example.mod.Main",
      requested: ["com.example.mod.Main"],
      class_sha256: "c".repeat(64),
      class_version: { major: 61, minor: 0, java_release: 17 },
      source_path: "com/example/mod/Main.java",
      text,
      sha256: createHash("sha256").update(text).digest("hex"),
      representation: "cfr-decompiled-java",
      cfr_reported_failures: false,
    },
  ],
  tool_profile: {
    decompiler: "CFR",
    release: "0.152",
    jar_path: "/tools/cfr-0.152.jar",
    jar_sha256: "f".repeat(64),
    java_command: "java",
    java_version: "openjdk version 21",
    arguments: [],
    timeout_ms: 1,
    output_budget_bytes: 1,
  },
  runtime_execution: "not-performed",
  limitations: [],
});
const service = (value: JvmArtifact, sha256 = value.artifact.sha256) =>
  new JvmArtifactService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "cfr", name: "CFR", version: "cfr@0.152" },
            { subject: { path: PATH, format: "file", sha256 } },
          ),
        ),
      ),
  });

it.each([
  { path: "relative.jar" },
  { path: PATH, classes: ["com.example.Main; rm -rf /"] },
  { path: PATH, decompile_all: true },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new JvmArtifactService({
    close: () => Promise.resolve(),
    inspect: () => {
      throw new Error("Must not execute");
    },
  });
  expect(await unused.inspect(input)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it.each(["path", "digest", "source-hash", "missing-class"])(
  "rejects a provider observation that drifts from the selection: %s",
  async (problem) => {
    const value = report();
    const [source] = value.decompiled;
    if (source === undefined) throw new Error("fixture has a source");
    if (problem === "path") value.artifact.path = "/different.jar";
    if (problem === "source-hash") source.sha256 = "b".repeat(64);
    expect(
      await service(
        value,
        problem === "digest" ? "b".repeat(64) : value.artifact.sha256,
      ).inspect({
        path: PATH,
        classes:
          problem === "missing-class"
            ? ["com.example.mod.Main", "com.example.mod.Other"]
            : ["com.example.mod.Main"],
      }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
  },
);

it("records decompiled sources as derived Evidence", async () => {
  expect(
    await service(report()).inspect({
      path: PATH,
      classes: ["com.example.mod.Main"],
    }),
  ).toMatchObject({
    ok: true,
    value: {
      operation: "inspect_jvm_artifact",
      confidence: "derived",
      normalized_result: { decompiled: [{ text }] },
    },
  });
});
