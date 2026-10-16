import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { WasmModuleReport } from "../../domain/wasmmodule/wasmModule.js";
import { ok } from "../../domain/result.js";
import { WasmModuleService } from "./WasmModuleService.js";

const PATH = "/games/web/Build/game.wasm";
const DIGEST = "a".repeat(64);
const row = (
  index: number,
  name: string,
): WasmModuleReport["functions"][number] => ({
  index,
  name,
  imported: false,
  type: "() -> ()",
  offset: 10,
  size: 4,
  locals: 0,
  calls: 0,
  indirect_calls: 0,
  callers: 0,
  decoded: true,
});
const report = (): WasmModuleReport => ({
  module: {
    path: PATH,
    sha256: DIGEST,
    bytes: 10,
    compression: "none",
    decompressed_bytes: 10,
    decompressed_sha256: DIGEST,
    name: null,
  },
  toolchain: {
    producers: [],
    target_features: [],
    detected: [],
    debug: {
      dwarf: false,
      source_map_url: null,
      external_debug_info: null,
      function_names: true,
    },
  },
  summary: {
    types: 1,
    imports: 0,
    functions: 1,
    imported_functions: 0,
    exports: 0,
    tables: 0,
    memories: [],
    globals: 0,
    data_segments: 0,
    data_bytes: 0,
    code_bytes: 4,
    start: null,
    undecoded_functions: 0,
  },
  page: {
    view: "functions",
    function: "main",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  sections: [],
  imports: [],
  exports: [],
  functions: [row(0, "main")],
  calls: [],
  data: [],
  strings: [],
  custom: [],
  limitations: [],
});
const service = (value: WasmModuleReport) =>
  new WasmModuleService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "wasm", name: "wasm", version: "1" },
            { subject: { path: PATH, format: "file", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, function: "main", limit: 1 };

it.each([
  { path: "game.wasm" },
  { path: PATH, view: "disassembly" },
  { path: PATH, view: "calls" },
  { path: PATH, function: -1 },
  { path: PATH, min_string_length: 2 },
  { path: PATH, limit: 1001 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new WasmModuleService({
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

it.each(["path", "view", "function", "rows", "page", "digest", "other view"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.module.path = "/other.wasm";
    if (problem === "view") value.page.view = "imports";
    if (problem === "function") value.functions = [row(1, "helper")];
    if (problem === "rows") value.functions.push(row(0, "main"));
    if (problem === "page") value.page.offset = 2;
    if (problem === "digest") value.module.sha256 = "b".repeat(64);
    if (problem === "other view")
      value.imports = [
        {
          index: 0,
          module: "env",
          name: "f",
          kind: "function",
          type: "() -> ()",
        },
      ];
    expect(await service(value).inspect(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the module as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_wasm_module", confidence: "observed" },
  });
});
