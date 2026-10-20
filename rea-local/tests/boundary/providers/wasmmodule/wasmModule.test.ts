import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { brotliCompressSync, gzipSync } from "node:zlib";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createWasmModuleService } from "../../../../src/composition/wasmModule.js";
import type { WasmModuleReport } from "../../../../src/domain/wasmmodule/wasmModule.js";
import {
  COMPONENT_PREAMBLE,
  createWasmModule,
  WASM_FIXTURE,
} from "../../../fixtures/wasmModuleFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/** V8's own decoder, typed here because the project's lib settings omit WebAssembly values. */
interface EngineModule {
  readonly brand?: never;
}
const V8 = (
  globalThis as unknown as {
    readonly WebAssembly: {
      readonly Module: (new (bytes: Uint8Array) => EngineModule) & {
        imports(
          module: EngineModule,
        ): { module: string; name: string; kind: string }[];
        exports(module: EngineModule): { name: string; kind: string }[];
        customSections(module: EngineModule, name: string): ArrayBuffer[];
      };
    };
  }
).WebAssembly.Module;

const service = createWasmModuleService();
let root = "";
const paths = { plain: "", gzip: "", brotli: "", undecodable: "" };
const MODULE = createWasmModule();

beforeAll(async () => {
  root = (await createTestWorkspace("rea-wasm-module-")).root;
  paths.plain = join(root, "game.wasm");
  paths.gzip = join(root, "game.wasm.gz");
  paths.brotli = join(root, "game.wasm.br");
  paths.undecodable = join(root, "undecodable.wasm");
  await writeFile(paths.plain, MODULE);
  await writeFile(paths.gzip, gzipSync(MODULE));
  await writeFile(paths.brotli, brotliCompressSync(MODULE));
  await writeFile(paths.undecodable, createWasmModule({ undecodable: true }));
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as WasmModuleReport;
};

const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

describe("WebAssembly module summary", () => {
  it("reads plain, gzip and Brotli modules alike", async () => {
    const plain = await inspect({ path: paths.plain });
    expect(plain.module).toEqual({
      path: paths.plain,
      sha256: sha256(MODULE),
      bytes: MODULE.length,
      compression: "none",
      decompressed_bytes: MODULE.length,
      decompressed_sha256: sha256(MODULE),
      name: "fixture",
    });
    for (const [path, compression] of [
      [paths.gzip, "gzip"],
      [paths.brotli, "brotli"],
    ] as const) {
      const report = await inspect({ path });
      expect(report.module).toMatchObject({
        compression,
        sha256: sha256(await readFile(path)),
        decompressed_bytes: MODULE.length,
        decompressed_sha256: sha256(MODULE),
      });
      expect(report.summary).toEqual(plain.summary);
      expect(report.functions).toEqual(plain.functions);
    }
    expect(plain.summary).toMatchObject({
      types: 3,
      imports: 3,
      functions: 4,
      imported_functions: 1,
      exports: 4,
      tables: 1,
      memories: [{ minimum: 1, maximum: 16, shared: false, memory64: false }],
      globals: 2,
      data_segments: 3,
      data_bytes: 37 + 20 + 13,
      start: 3,
      undecoded_functions: 0,
    });
  });

  it("reports the toolchain and debug information the module kept", async () => {
    const { toolchain } = await inspect({ path: paths.plain });
    expect(toolchain).toEqual({
      producers: [
        { field: "language", name: "C", version: "" },
        { field: "processed-by", name: "clang", version: "19.1.0" },
      ],
      target_features: ["+simd128", "+bulk-memory"],
      detected: ["emscripten", "clang"],
      debug: {
        dwarf: true,
        source_map_url: WASM_FIXTURE.sourceMap,
        external_debug_info: WASM_FIXTURE.debugFile,
        function_names: true,
      },
    });
  });
});

describe("WebAssembly module functions and calls", () => {
  it("lists functions with names, signatures and call counts", async () => {
    const report = await inspect({ path: paths.plain });
    expect(
      report.functions.map((row) => [
        row.index,
        row.name,
        row.imported,
        row.type,
        row.locals,
        row.calls,
        row.indirect_calls,
        row.callers,
        row.decoded,
      ]),
    ).toEqual([
      [
        0,
        "env.emscripten_run_script",
        true,
        WASM_FIXTURE.types[0],
        null,
        0,
        0,
        1,
        true,
      ],
      [1, "add", false, WASM_FIXTURE.types[1], 0, 0, 0, 2, true],
      [2, "main", false, WASM_FIXTURE.types[2], 2, 3, 1, 0, true],
      [3, "helper_export", false, WASM_FIXTURE.types[2], 0, 1, 0, 1, true],
    ]);
    const bodies = report.functions.slice(1);
    expect(bodies.reduce((sum, row) => sum + (row.size ?? 0), 0)).toBe(
      report.summary.code_bytes,
    );
    const page = await inspect({ path: paths.plain, offset: 1, limit: 2 });
    expect(page.page).toMatchObject({ total: 4, returned: 2 });
    expect(page.functions.map(({ index }) => index)).toEqual([1, 2]);
    const named = await inspect({ path: paths.plain, function: "main" });
    expect(named.functions.map(({ index }) => index)).toEqual([2]);
    const query = await inspect({ path: paths.plain, query: "ADD" });
    expect(query.functions.map(({ name }) => name)).toEqual(["add"]);
  });

  it("lists the callees and callers of one function", async () => {
    const main = await inspect({
      path: paths.plain,
      view: "calls",
      function: 2,
    });
    expect(main.calls).toEqual([
      {
        direction: "callee",
        index: 0,
        name: "env.emscripten_run_script",
        sites: 1,
      },
      { direction: "callee", index: 1, name: "add", sites: 2 },
      { direction: "callee", index: 3, name: "helper_export", sites: 1 },
    ]);
    const add = await inspect({
      path: paths.plain,
      view: "calls",
      function: "add",
    });
    expect(add.calls).toEqual([
      { direction: "caller", index: 2, name: "main", sites: 2 },
      { direction: "caller", index: 3, name: "helper_export", sites: 1 },
    ]);
    expect(add.page.function).toBe("add");
  });

  it("marks a body with an unknown opcode as undecoded", async () => {
    const report = await inspect({ path: paths.undecodable });
    expect(report.summary.undecoded_functions).toBe(1);
    expect(report.functions.at(-1)).toMatchObject({ index: 4, decoded: false });
  });
});

describe("WebAssembly module boundary, data and sections", () => {
  it("lists imports and exports as the engine sees them", async () => {
    const imports = await inspect({ path: paths.plain, view: "imports" });
    expect(imports.imports).toEqual([
      {
        index: 0,
        module: "env",
        name: "emscripten_run_script",
        kind: "function",
        type: WASM_FIXTURE.types[0],
      },
      {
        index: 0,
        module: "env",
        name: "memory",
        kind: "memory",
        type: "1..16 pages",
      },
      {
        index: 0,
        module: "env",
        name: "__stack_pointer",
        kind: "global",
        type: "mut i32",
      },
    ]);
    const exports = await inspect({ path: paths.plain, view: "exports" });
    expect(
      exports.exports.map(({ name, kind, target }) => [name, kind, target]),
    ).toEqual([
      ["add", "function", "add"],
      ["main", "function", "main"],
      ["helper_export", "function", "helper_export"],
      ["memory", "memory", null],
    ]);
    const compiled = new V8(MODULE);
    expect(
      imports.imports.map(({ module, name, kind }) => ({ module, name, kind })),
    ).toEqual(V8.imports(compiled));
    expect(exports.exports.map(({ name, kind }) => ({ name, kind }))).toEqual(
      V8.exports(compiled),
    );
  });

  it("lists data segments and the text inside them", async () => {
    const data = await inspect({ path: paths.plain, view: "data" });
    expect(
      data.data.map(({ index, name, mode, memory, address, size }) => [
        index,
        name,
        mode,
        memory,
        address,
        size,
      ]),
    ).toEqual([
      [0, "greetings", "active", 0, 1024, 37],
      [1, null, "passive", null, null, 20],
      [2, null, "active", 0, 2048, 13],
    ]);
    const strings = await inspect({ path: paths.plain, view: "strings" });
    expect(
      strings.strings.map(({ segment, address, text }) => [
        segment,
        address,
        text,
      ]),
    ).toEqual([
      [0, 1024, WASM_FIXTURE.greeting],
      [0, 1044, WASM_FIXTURE.health],
      [1, null, WASM_FIXTURE.passive],
      [2, 2050, WASM_FIXTURE.score],
    ]);
    for (const { offset, text } of strings.strings)
      expect(
        MODULE.subarray(offset, offset + text.length).toString("latin1"),
      ).toBe(text);
    const longer = await inspect({
      path: paths.plain,
      view: "strings",
      min_string_length: 15,
    });
    expect(longer.strings.map(({ text }) => text)).toEqual([
      WASM_FIXTURE.greeting,
      WASM_FIXTURE.passive,
    ]);
  });

  it("lists sections and custom sections", async () => {
    const sections = await inspect({ path: paths.plain, view: "sections" });
    expect(
      sections.sections.map(({ name, entries }) => [name, entries]),
    ).toEqual([
      ["type", 3],
      ["import", 3],
      ["function", 3],
      ["table", 1],
      ["global", 1],
      ["export", 4],
      ["start", null],
      ["code", 3],
      ["data", 3],
      ["name", null],
      ["producers", null],
      ["target_features", null],
      ["sourceMappingURL", null],
      ["external_debug_info", null],
      [".debug_info", null],
    ]);
    const custom = await inspect({ path: paths.plain, view: "custom" });
    expect(custom.custom.map(({ name, preview }) => [name, preview])).toEqual([
      ["name", null],
      ["producers", null],
      ["target_features", null],
      ["sourceMappingURL", WASM_FIXTURE.sourceMap],
      ["external_debug_info", WASM_FIXTURE.debugFile],
      [".debug_info", null],
    ]);
    const compiled = new V8(MODULE);
    for (const { name, size } of custom.custom)
      expect(
        V8.customSections(compiled, name).map((buffer) => buffer.byteLength),
      ).toEqual([size]);
  });
});

describe("WebAssembly module refusals", () => {
  it("refuses files that are not core modules", async () => {
    const files = {
      "notes.txt": Buffer.from("not wasm"),
      "component.wasm": COMPONENT_PREAMBLE,
      "truncated.wasm": MODULE.subarray(0, 40),
      "broken.wasm.gz": gzipSync(MODULE).subarray(0, 30),
    };
    for (const [name, bytes] of Object.entries(files)) {
      const path = join(root, name);
      await writeFile(path, bytes);
      expect(await service.inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              path: ["path"],
              message: expect.stringContaining(
                "Not a readable WebAssembly module",
              ),
            },
          ],
        },
      });
    }
    const component = await service.inspect({
      path: join(root, "component.wasm"),
    });
    expect(JSON.stringify(component)).toContain("component-model");
  });

  it("refuses function selections the module does not have", async () => {
    for (const input of [
      { path: paths.plain, view: "calls" },
      { path: paths.plain, view: "calls", function: 99 },
      { path: paths.plain, function: "missing" },
    ])
      expect(await service.inspect(input)).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError", issues: [{ path: ["function"] }] },
      });
  });
});

/** A folder of real modules, such as web game builds; V8 decodes each one independently. */
const REAL = process.env["REA_VERIFY_WASM_DIR"];
const COMPRESSORS = {
  gzip: process.env["REA_VERIFY_GZIP_BIN"],
  brotli: process.env["REA_VERIFY_BROTLI_BIN"],
};

const modulesUnder = async (directory: string): Promise<string[]> => {
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(directory, {
    recursive: true,
    withFileTypes: true,
  });
  return entries
    .filter(
      (entry) =>
        entry.isFile() && /\.wasm(?:\.gz|\.br)?$|\.unityweb$/u.test(entry.name),
    )
    .map((entry) => join(entry.parentPath, entry.name))
    .sort();
};

/** Every row of one view, page by page. */
const allRows = async <View extends "imports" | "exports" | "custom">(
  path: string,
  view: View,
) => {
  const rows: WasmModuleReport[View] = [];
  for (let offset = 0; ; offset += 1000) {
    const report = await inspect({ path, view, offset, limit: 1000 });
    rows.push(...(report[view] as never[]));
    if (offset + 1000 >= report.page.total) return { report, rows };
  }
};

describe.skipIf(REAL === undefined)("real WebAssembly modules", () => {
  it("decodes every module as V8 does", async () => {
    const paths = await modulesUnder(REAL ?? "");
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      const { report, rows: imports } = await allRows(path, "imports");
      const { rows: exports } = await allRows(path, "exports");
      const { rows: custom } = await allRows(path, "custom");
      const { decompressModule } =
        await import("../../../../src/wasmmodule/WasmModuleReport.js");
      const compiled = new V8(decompressModule(await readFile(path)).bytes);
      expect(
        imports.map(({ module, name, kind }) => ({ module, name, kind })),
        path,
      ).toEqual(V8.imports(compiled));
      expect(
        exports.map(({ name, kind }) => ({ name, kind })),
        path,
      ).toEqual(V8.exports(compiled));
      for (const { name, size } of custom)
        expect(
          V8.customSections(compiled, name).map((buffer) => buffer.byteLength),
          `${path} ${name}`,
        ).toContain(size);
      expect(report.summary.undecoded_functions, path).toBe(0);
      expect(report.summary.imports, path).toBe(imports.length);
    }
  }, 900_000);

  it.each(Object.entries(COMPRESSORS).filter(([, bin]) => bin !== undefined))(
    "reads a real module compressed by the %s tool",
    async (name, bin) => {
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const [path] = await modulesUnder(REAL ?? "");
      const plain = await inspect({ path, limit: 1 });
      const target = join(root, `real.wasm.${name === "gzip" ? "gz" : "br"}`);
      await promisify(execFile)(bin ?? name, ["-c", "-6", path ?? ""], {
        encoding: "buffer",
        maxBuffer: 1024 ** 3,
      }).then(({ stdout }) => writeFile(target, stdout));
      const compressed = await inspect({ path: target, limit: 1 });
      expect(compressed.module).toMatchObject({
        compression: name,
        decompressed_sha256: plain.module.decompressed_sha256,
      });
      expect(compressed.summary).toEqual(plain.summary);
    },
    300_000,
  );
});
