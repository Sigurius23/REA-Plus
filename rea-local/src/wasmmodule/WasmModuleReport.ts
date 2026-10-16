import { createHash } from "node:crypto";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

import type {
  InspectWasmModuleInput,
  WasmModuleReport,
} from "../domain/wasmmodule/wasmModule.js";
import { readModule, type Module } from "./WasmModule.js";
import {
  WasmFormatError,
  WasmReader,
  WasmSelectionError,
} from "./WasmReader.js";

type Report = WasmModuleReport;
type View = InspectWasmModuleInput["view"];
type Rows = Pick<Report, View>;

const MAX_MODULE_BYTES = 1024 * 1024 * 1024;
const MAX_STRING_CHARS = 1000;

/** Undo the gzip or Brotli wrapping web builds ship (.wasm.gz, .wasm.br, .unityweb). */
export const decompressModule = (
  bytes: Buffer,
): {
  readonly bytes: Buffer;
  readonly compression: Report["module"]["compression"];
} => {
  if (bytes.length >= 4 && bytes.readUInt32LE(0) === 0x6d736100)
    return { bytes, compression: "none" };
  const options = { maxOutputLength: MAX_MODULE_BYTES };
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    try {
      return { bytes: gunzipSync(bytes, options), compression: "gzip" };
    } catch (cause) {
      throw new WasmFormatError("The gzip stream does not decompress.", {
        cause,
      });
    }
  }
  try {
    const decompressed = brotliDecompressSync(bytes, options);
    if (decompressed.readUInt32LE(0) === 0x6d736100)
      return { bytes: decompressed, compression: "brotli" };
  } catch {
    // Not Brotli either; reported below.
  }
  throw new WasmFormatError(
    "Not a WebAssembly module, nor a gzip- or Brotli-compressed one.",
  );
};

const importedFunctions = (module: Module) =>
  module.imports.filter(({ kind }) => kind === "function");

/** Function names: the name section, then exports, then the import's own name. */
const functionNames = (module: Module): (string | null)[] => {
  const imported = importedFunctions(module);
  const total = imported.length + module.functions.length;
  const exported = new Map<number, string>();
  for (const entry of module.exports)
    if (entry.kind === "function" && !exported.has(entry.index))
      exported.set(entry.index, entry.name);
  return Array.from({ length: total }, (_, index) => {
    const imp = imported[index];
    return (
      module.names.functions.get(index) ??
      exported.get(index) ??
      (imp === undefined ? null : `${imp.module}.${imp.name}`)
    );
  });
};

interface Probe {
  readonly names: readonly (string | null)[];
  /** Whether any data segment contains the marker text. */
  readonly data: (marker: string) => boolean;
}

const DETECTORS: readonly (readonly [
  string,
  (module: Module, probe: Probe) => boolean,
])[] = [
  [
    "emscripten",
    (m) =>
      m.imports.some(({ name }) => /^_?emscripten_/u.test(name)) ||
      m.exports.some(({ name }) => /emscripten/u.test(name)),
  ],
  // -O2+ builds with MINIFY_WASM_IMPORTED_MODULES import everything from module "a".
  [
    "emscripten-minified",
    (m) =>
      m.imports.length > 0 && m.imports.every(({ module }) => module === "a"),
  ],
  // Minified Unity and Godot builds keep their engine's names in data strings.
  [
    "unity-webgl",
    (m, probe) =>
      m.imports.some(({ name }) => name.startsWith("_JS_")) ||
      probe.data("UnityEngine."),
  ],
  [
    "il2cpp",
    (_m, probe) =>
      probe.names.some((name) => name?.startsWith("il2cpp_") === true) ||
      probe.data("il2cpp"),
  ],
  [
    "godot",
    (m, probe) =>
      m.imports.some(({ name }) => name.startsWith("godot_js_")) ||
      probe.data("Godot Engine"),
  ],
  [
    "wasm-bindgen",
    (m) =>
      m.imports.some(
        ({ module, name }) =>
          module === "__wbindgen_placeholder__" || name.startsWith("__wbg_"),
      ),
  ],
  [
    "rust",
    (m, probe) =>
      m.producers.some(({ name }) => /rust/iu.test(name)) ||
      probe.data("/rustc/"),
  ],
  ["bevy", (_m, probe) => probe.data("bevy_")],
  [
    "go",
    (m) => m.imports.some(({ module }) => module === "go" || module === "gojs"),
  ],
  ["tinygo", (m) => m.producers.some(({ name }) => /tinygo/iu.test(name))],
  [
    "dotnet",
    (m) =>
      m.imports.some(({ name }) => name.startsWith("mono_wasm_")) ||
      m.exports.some(({ name }) => name.startsWith("mono_wasm_")),
  ],
  ["wasi", (m) => m.imports.some(({ module }) => module.startsWith("wasi_"))],
  ["clang", (m) => m.producers.some(({ name }) => /clang/iu.test(name))],
];

const TEXT = /^[^\p{Cc}\uFFFD]+$/u;

/** A custom section whose content is one name (sourceMappingURL, external_debug_info). */
const nameContent = (
  bytes: Buffer,
  section: { offset: number; size: number },
): string | null => {
  try {
    const reader = new WasmReader(
      bytes,
      section.offset,
      section.offset + section.size,
    );
    const text = reader.name();
    // Binary sections can happen to start with a plausible length; keep only clean text.
    return reader.done && TEXT.test(text) ? text : null;
  } catch {
    return null;
  }
};

const toolchainOf = (
  module: Module,
  bytes: Buffer,
  names: readonly (string | null)[],
): Report["toolchain"] => {
  const custom = (name: string) =>
    module.custom.find((section) => section.name === name);
  const text = (name: string) => {
    const section = custom(name);
    return section === undefined ? null : nameContent(bytes, section);
  };
  const probe: Probe = {
    names,
    data: (marker) =>
      module.data.some(
        ({ offset, size }) =>
          bytes.subarray(offset, offset + size).indexOf(marker) >= 0,
      ),
  };
  return {
    producers: module.producers,
    target_features: module.features,
    detected: DETECTORS.filter(([, test]) => test(module, probe)).map(
      ([name]) => name,
    ),
    debug: {
      dwarf: module.custom.some(({ name }) => name.startsWith(".debug_")),
      source_map_url: text("sourceMappingURL"),
      external_debug_info: text("external_debug_info"),
      function_names: module.names.functions.size > 0,
    },
  };
};

/** Printable ASCII runs in data segments, with their memory addresses. */
const stringsOf = (
  module: Module,
  bytes: Buffer,
  minimum: number,
): Report["strings"] => {
  const strings: Report["strings"] = [];
  module.data.forEach((segment, index) => {
    let start = -1;
    const flush = (end: number) => {
      if (start >= 0 && end - start >= minimum) {
        const text = bytes
          .subarray(start, Math.min(end, start + MAX_STRING_CHARS))
          .toString("latin1");
        strings.push({
          segment: index,
          address:
            segment.address === null
              ? null
              : segment.address + (start - segment.offset),
          offset: start,
          text,
        });
      }
      start = -1;
    };
    for (let at = segment.offset; at < segment.offset + segment.size; at += 1) {
      const byte = bytes[at] ?? 0;
      const printable = (byte >= 0x20 && byte < 0x7f) || byte === 0x09;
      if (printable && start < 0) start = at;
      else if (!printable) flush(at);
    }
    flush(segment.offset + segment.size);
  });
  return strings;
};

interface Context {
  readonly module: Module;
  readonly bytes: Buffer;
  readonly names: readonly (string | null)[];
  readonly callers: readonly Map<number, number>[];
  readonly input: InspectWasmModuleInput;
}

const matches = (
  query: string | undefined,
  ...values: (string | null)[]
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

/** Resolve the selected function by index or exact name. */
const selectedFunction = (context: Context): number | null => {
  const selected = context.input.function;
  if (selected === undefined) return null;
  if (typeof selected === "number") {
    if (selected >= context.names.length)
      throw new WasmSelectionError(
        `No function ${String(selected)}; the module has ${String(context.names.length)}.`,
      );
    return selected;
  }
  const index = context.names.indexOf(selected);
  if (index < 0) throw new WasmSelectionError(`No function named ${selected}.`);
  return index;
};

const functionRows = (context: Context): Report["functions"] => {
  const { module, names, callers } = context;
  const imported = importedFunctions(module);
  return names.map((name, index) => {
    const imp = imported[index];
    const body =
      imp === undefined ? module.bodies[index - imported.length] : undefined;
    const type =
      imp?.type ??
      module.types[module.functions[index - imported.length] ?? -1] ??
      "?";
    return {
      index,
      name,
      imported: imp !== undefined,
      type,
      offset: body?.offset ?? null,
      size: body?.size ?? null,
      locals: body?.locals ?? null,
      calls: body?.calls.size ?? 0,
      indirect_calls: body?.indirect ?? 0,
      callers: callers[index]?.size ?? 0,
      decoded: body?.decoded ?? true,
    };
  });
};

const callRows = (
  context: Context,
  selected: number | null,
): Report["calls"] => {
  if (selected === null)
    throw new WasmSelectionError(
      "The calls view needs a function (index or name).",
    );
  const imported = importedFunctions(context.module).length;
  const body = context.module.bodies[selected - imported];
  const row = (
    direction: "callee" | "caller",
    index: number,
    sites: number,
  ) => ({
    direction,
    index,
    name: context.names[index] ?? null,
    sites,
  });
  return [
    ...[...(body?.calls ?? new Map<number, number>())].map(([index, sites]) =>
      row("callee", index, sites),
    ),
    ...[...(context.callers[selected] ?? new Map<number, number>())].map(
      ([index, sites]) => row("caller", index, sites),
    ),
  ];
};

const viewRows = (context: Context): readonly unknown[] => {
  const { module, bytes, names, input } = context;
  const { query } = input;
  const selected = selectedFunction(context);
  switch (input.view) {
    case "sections":
      return module.sections.filter((row) => matches(query, row.name));
    case "imports":
      return module.imports.filter((row) =>
        matches(query, row.module, row.name),
      );
    case "exports":
      return module.exports
        .map((row) => ({
          ...row,
          target: row.kind === "function" ? (names[row.index] ?? null) : null,
        }))
        .filter((row) => matches(query, row.name, row.target));
    case "functions":
      return functionRows(context).filter(
        (row) =>
          (selected === null || row.index === selected) &&
          matches(query, row.name),
      );
    case "calls":
      return callRows(context, selected).filter((row) =>
        matches(query, row.name),
      );
    case "data":
      return module.data
        .map((segment, index) => ({
          index,
          name: module.names.data.get(index) ?? null,
          ...segment,
        }))
        .filter((row) => matches(query, row.name));
    case "strings":
      return stringsOf(module, bytes, input.min_string_length).filter((row) =>
        matches(query, row.text),
      );
    default:
      return module.custom
        .map((section) => ({
          ...section,
          preview: section.size <= 4096 ? nameContent(bytes, section) : null,
        }))
        .filter((row) => matches(query, row.name, row.preview));
  }
};

const summaryOf = (module: Module): Report["summary"] => {
  const imports = (kind: string) =>
    module.imports.filter((entry) => entry.kind === kind).length;
  return {
    types: module.types.length,
    imports: module.imports.length,
    functions: imports("function") + module.functions.length,
    imported_functions: imports("function"),
    exports: module.exports.length,
    tables: imports("table") + module.tables,
    memories: module.memories,
    globals: imports("global") + module.globals,
    data_segments: module.data.length,
    data_bytes: module.data.reduce((sum, segment) => sum + segment.size, 0),
    code_bytes: module.bodies.reduce((sum, body) => sum + body.size, 0),
    start: module.start,
    undecoded_functions: module.bodies.filter(({ decoded }) => !decoded).length,
  };
};

/** Decode a (possibly compressed) module into the summary and one paged view. */
export const buildWasmModuleReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectWasmModuleInput,
  limitations: readonly string[],
): Report => {
  const { bytes, compression } = decompressModule(file.bytes);
  const module = readModule(bytes);
  const names = functionNames(module);
  const imported = importedFunctions(module).length;
  const callers = names.map(() => new Map<number, number>());
  module.bodies.forEach((body, position) => {
    for (const [callee, sites] of body.calls)
      callers[callee]?.set(imported + position, sites);
  });
  const context: Context = { module, bytes, names, callers, input };
  const matching = viewRows(context);
  const page = matching.slice(input.offset, input.offset + input.limit);
  const empty: Rows = {
    sections: [],
    imports: [],
    exports: [],
    functions: [],
    calls: [],
    data: [],
    strings: [],
    custom: [],
  };
  return {
    module: {
      path: input.path,
      sha256: file.sha256,
      bytes: file.bytes.length,
      compression,
      decompressed_bytes: bytes.length,
      decompressed_sha256:
        compression === "none"
          ? file.sha256
          : createHash("sha256").update(bytes).digest("hex"),
      name: module.names.module,
    },
    toolchain: toolchainOf(module, bytes, names),
    summary: summaryOf(module),
    page: {
      view: input.view,
      function: input.function ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    ...empty,
    [input.view]: page,
    limitations: [...limitations],
  };
};
