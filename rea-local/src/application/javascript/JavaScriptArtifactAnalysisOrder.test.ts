import { createHash } from "node:crypto";

import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { ok } from "../../domain/result.js";
import { analyzeAndAdoptJavaScriptArtifactFiles } from "./JavaScriptArtifactAnalysis.js";
import { createJavaScriptSemanticGraphProjection } from "./JavaScriptSemanticGraphBuilder.js";

const source = (path: string, value: string): JavaScriptArtifactFile => ({
  path,
  sha256: createHash("sha256").update(value).digest("hex"),
  container_sha256: "1".repeat(64),
  bytes: Buffer.byteLength(value),
  inventory_artifact_id: "fixture-source",
  kind: "javascript",
  unpacked: false,
  text: { included: true, value },
});

it("analyzes JavaScript smallest first in place and reports inventory order", async () => {
  const files = [
    source("vendor.js", `fetch("/vendor");${" ".repeat(4096)}`),
    { ...source("data.json", "{}"), kind: "json" as const },
    source("app.js", `fetch("/app");${" ".repeat(64)}`),
    source("tiny.js", `fetch("/tiny");`),
  ];
  const analyzed: string[] = [];
  const order: string[] = [];
  const { analysis, interruption } =
    await analyzeAndAdoptJavaScriptArtifactFiles(
      { files, containers: [], text_bytes_read: 0, invalid_utf8_files: 0 },
      {
        analyze: async (file) => {
          analyzed.push(file.path);
          if (!file.text.included) throw new Error("Source text is missing");
          return ok({
            javascript: analyzeJavaScriptStaticSource(file.text.value),
            module: null,
            projection: null,
          });
        },
      },
      createJavaScriptSemanticGraphProjection(),
      async (file) => {
        order.push(file.path);
      },
    );
  expect(interruption).toBeNull();
  expect(analyzed).toEqual(["tiny.js", "app.js", "vendor.js"]);
  expect(order).toEqual(["tiny.js", "data.json", "app.js", "vendor.js"]);
  expect(analysis.files.map(({ file }) => file.path)).toEqual([
    "vendor.js",
    "data.json",
    "app.js",
    "tiny.js",
  ]);
});
