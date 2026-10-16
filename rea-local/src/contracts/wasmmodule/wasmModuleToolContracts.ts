import {
  inspectWasmModuleInputSchema,
  wasmModuleSchema,
} from "../../domain/wasmmodule/wasmModule.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free WebAssembly module reader with CLI/MCP parity; nothing is compiled or run. */
export const WASM_MODULE_TOOL_CONTRACTS = [
  {
    name: "inspect_wasm_module",
    ...toolContractMetadata("inspect_wasm_module"),
    kind: "artifact-provider",
    description:
      "Decode a local WebAssembly core module (.wasm, or the gzip/Brotli-compressed .wasm.gz, .wasm.br and .unityweb files web game builds ship) without WABT, Binaryen or a JavaScript engine, and return Evidence of the module: hashes of the file and the decompressed module, the toolchain it names or betrays (producers, target features, Emscripten, Unity WebGL, IL2CPP, Godot, wasm-bindgen, Go, .NET, WASI), what debug information it kept (name section, DWARF, source map URL), counts, then one paged view. functions lists every function with its name, signature, body offset and size and direct call counts; calls lists the callees and callers of one function; imports and exports list the module's boundary with JavaScript; data and strings list data segments and the printable text in them; sections and custom list the section table. Nothing is compiled or run.",
    inputSchema: inspectWasmModuleInputSchema,
    outputSchema: evidenceResultOf(wasmModuleSchema),
    examples: [
      {
        title: "List the functions of a web game module",
        input: { path: "/games/web/Build/game.wasm" },
      },
      {
        title: "Find who calls a function in a compressed Unity build",
        input: {
          path: "/games/web/Build/game.wasm.br",
          view: "calls",
          function: "il2cpp_init",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
