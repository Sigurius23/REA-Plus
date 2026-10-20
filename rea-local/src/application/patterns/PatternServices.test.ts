import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { BytePatternScan } from "../../domain/patterns/bytePatterns.js";
import { ok } from "../../domain/result.js";
import { BytePatternService } from "./BytePatternService.js";
import { CheatTableService } from "./CheatTableService.js";

const PATH = "/games/GameAssembly.dll";
const scan = (): BytePatternScan => ({
  file: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 1,
    format: "raw",
    architecture: null,
    image_base: null,
    layout_error: null,
    sections: [],
  },
  scanned: { scope: "file", regions: ["<file>"], bytes: 1 },
  results: [
    {
      name: "p",
      pattern: "90",
      length: 1,
      total_matches: 0,
      complete: true,
      matches: [],
    },
  ],
  limitations: [],
});
const execution = (value: unknown) =>
  Promise.resolve(
    ok(
      createAnalysisExecution(
        value as BytePatternScan,
        { id: "scan", name: "scan", version: "1" },
        { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
      ),
    ),
  );
const scanner = (value: BytePatternScan) =>
  new BytePatternService({
    close: () => Promise.resolve(),
    scan: () => execution(value),
  });
const INPUT = { path: PATH, patterns: [{ name: "p", pattern: "90" }] };

it.each([
  { path: "x.dll", patterns: [{ pattern: "90" }] },
  { path: PATH, patterns: [] },
  { path: PATH, patterns: [{ pattern: "90" }], max_matches: 1001 },
])("rejects invalid scans before effects: %j", async (input) => {
  const unused = new BytePatternService({
    close: () => Promise.resolve(),
    scan: () => {
      throw new Error("Must not execute");
    },
  });
  expect(await unused.scan(input)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it.each(["name", "count", "path"])(
  "rejects a scan report that drifts: %s",
  async (problem) => {
    const value = scan();
    const [result] = value.results;
    if (problem === "name" && result !== undefined) result.name = "q";
    if (problem === "count" && result !== undefined)
      result.matches = [
        {
          file_offset: 0,
          address: null,
          rva: null,
          section: null,
          bytes: "90",
          displacements: [],
        },
      ];
    if (problem === "path") value.file.path = "/other.dll";
    expect(await scanner(value).scan(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records scans as observed Evidence and validates table paths", async () => {
  expect(await scanner(scan()).scan(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "scan_byte_patterns", confidence: "observed" },
  });
  const tables = new CheatTableService({
    close: () => Promise.resolve(),
    inspect: () => {
      throw new Error("Must not execute");
    },
  });
  expect(
    await tables.inspect({ path: "/t.CT", binary_path: "game.exe" }),
  ).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError", issues: [{ path: ["binary_path"] }] },
  });
});
