import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();

export const WASM_MODULE_VIEWS = [
  "sections",
  "imports",
  "exports",
  "functions",
  "calls",
  "data",
  "strings",
  "custom",
] as const;

export const WASM_MODULE_PAGE_LIMIT = 1000;

export const inspectWasmModuleInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute WebAssembly module: .wasm, or gzip/Brotli-compressed .wasm.gz, .wasm.br or Unity .unityweb",
    ),
  view: z
    .enum(WASM_MODULE_VIEWS)
    .default("functions")
    .describe(
      "sections: section table; imports and exports; functions: every function with name, signature, body size and direct call counts; calls: callees and callers of the selected function; data: data segments; strings: printable text in data segments; custom: custom sections.",
    ),
  function: z
    .union([z.number().int().nonnegative(), z.string().min(1).max(512)])
    .optional()
    .describe(
      "Function index or name for the calls view (and a filter for functions)",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of names, import modules, section names or string text",
    ),
  min_string_length: z
    .number()
    .int()
    .min(4)
    .max(256)
    .default(6)
    .describe("Shortest printable run reported by the strings view"),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(WASM_MODULE_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

export const wasmSectionSchema = z.strictObject({
  id: count,
  name: z
    .string()
    .describe("Standard section name, or the custom section's name."),
  offset: count.describe("Offset of the payload in the decompressed module."),
  size: count,
  entries: count.nullable(),
});

export const wasmImportSchema = z.strictObject({
  index: count.describe(
    "Index in its kind's space (function, table, memory, global, tag).",
  ),
  module: z.string(),
  name: z.string(),
  kind: z.enum(["function", "table", "memory", "global", "tag"]),
  type: z.string().describe("Signature, limits or value type."),
});

export const wasmExportSchema = z.strictObject({
  name: z.string(),
  kind: z.enum(["function", "table", "memory", "global", "tag"]),
  index: count,
  target: z
    .string()
    .nullable()
    .describe("Name of the exported function, when known."),
});

export const wasmFunctionSchema = z.strictObject({
  index: count,
  name: z
    .string()
    .nullable()
    .describe("From the name section, an export, or the import."),
  imported: z.boolean(),
  type: z.string().describe("Signature, such as (i32, i32) -> i32."),
  offset: count.nullable().describe("Body offset in the decompressed module."),
  size: count.nullable().describe("Body size in bytes."),
  locals: count.nullable(),
  calls: count.describe(
    "Distinct functions called directly (call, return_call).",
  ),
  indirect_calls: count.describe("call_indirect and call_ref instructions."),
  callers: count.describe("Distinct functions that call this one directly."),
  decoded: z
    .boolean()
    .describe("The body decoded to its end; false stops at an unknown opcode."),
});

export const wasmCallSchema = z.strictObject({
  direction: z.enum(["callee", "caller"]),
  index: count,
  name: z.string().nullable(),
  sites: count.describe("Call instructions between the two functions."),
});

export const wasmDataSchema = z.strictObject({
  index: count,
  name: z.string().nullable(),
  mode: z.enum(["active", "passive"]),
  memory: count.nullable(),
  address: z
    .number()
    .int()
    .nullable()
    .describe("Load address when the offset is a constant."),
  offset: count.describe("Offset of the bytes in the decompressed module."),
  size: count,
});

export const wasmStringSchema = z.strictObject({
  segment: count,
  address: z
    .number()
    .int()
    .nullable()
    .describe("Memory address, when the segment's is constant."),
  offset: count,
  text: z.string(),
});

export const wasmCustomSchema = z.strictObject({
  name: z.string(),
  offset: count,
  size: count,
  preview: z
    .string()
    .nullable()
    .describe("Text content of small text sections."),
});

export const wasmModuleSchema = z.strictObject({
  module: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    compression: z.enum(["none", "gzip", "brotli"]),
    decompressed_bytes: count,
    decompressed_sha256: digest,
    name: z.string().nullable().describe("Module name from the name section."),
  }),
  toolchain: z.strictObject({
    producers: z.array(
      z.strictObject({
        field: z.string(),
        name: z.string(),
        version: z.string(),
      }),
    ),
    target_features: z.array(z.string()),
    detected: z
      .array(z.string())
      .describe(
        "Toolchains or engines the imports, exports, producers and marker strings in data point to.",
      ),
    debug: z.strictObject({
      dwarf: z.boolean(),
      source_map_url: z.string().nullable(),
      external_debug_info: z.string().nullable(),
      function_names: z.boolean(),
    }),
  }),
  summary: z.strictObject({
    types: count,
    imports: count,
    functions: count,
    imported_functions: count,
    exports: count,
    tables: count,
    memories: z.array(
      z.strictObject({
        minimum: count,
        maximum: count.nullable(),
        shared: z.boolean(),
        memory64: z.boolean(),
      }),
    ),
    globals: count,
    data_segments: count,
    data_bytes: count,
    code_bytes: count,
    start: count.nullable(),
    undecoded_functions: count,
  }),
  page: z.strictObject({
    view: z.enum(WASM_MODULE_VIEWS),
    function: z.union([count, z.string()]).nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  sections: z.array(wasmSectionSchema),
  imports: z.array(wasmImportSchema),
  exports: z.array(wasmExportSchema),
  functions: z.array(wasmFunctionSchema),
  calls: z.array(wasmCallSchema),
  data: z.array(wasmDataSchema),
  strings: z.array(wasmStringSchema),
  custom: z.array(wasmCustomSchema),
  limitations: z.array(z.string()),
});

export type InspectWasmModuleInput = z.output<
  typeof inspectWasmModuleInputSchema
>;
export type WasmModuleReport = z.output<typeof wasmModuleSchema>;
