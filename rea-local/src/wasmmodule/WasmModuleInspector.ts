import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { WasmModulePort } from "../application/wasmmodule/WasmModulePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  wasmModuleSchema,
  type InspectWasmModuleInput,
} from "../domain/wasmmodule/wasmModule.js";
import type { Result } from "../domain/result.js";
import { buildWasmModuleReport } from "./WasmModuleReport.js";
import { WasmFormatError, WasmSelectionError } from "./WasmReader.js";

const OPERATION = "inspect_wasm_module";

export const WASM_MODULE_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "wasm-module-reader",
  name: "REA+ WebAssembly module reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads WebAssembly core modules (version 1), plain or gzip/Brotli-compressed, without WABT, Binaryen or a JavaScript engine; nothing is compiled or run. Component-model binaries are refused.",
  "Direct calls come from call and return_call; call_indirect and call_ref targets depend on runtime tables and are counted, not resolved.",
  "Instruction decoding covers the core, SIMD, threads, bulk memory, reference types, exception handling, tail calls and GC proposals; a body with any other opcode is marked decoded: false.",
  "Function names come from the name section when the build kept it; otherwise from exports and imports. Strings are printable ASCII runs in data segments, not proven string values.",
  "Detected toolchains are indicators: import and export naming conventions, producers entries and engine marker strings in data (UnityEngine., il2cpp, Godot Engine, /rustc/, bevy_), not proof of how the module was built.",
];

const SPEC = {
  operation: OPERATION,
  identity: WASM_MODULE_PROVIDER_IDENTITY,
  maxFileBytes: 512 * 1024 * 1024,
  schema: wasmModuleSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: WasmSelectionError, field: "function" }],
  formatErrors: [WasmFormatError, RangeError],
  notReadable: "Not a readable WebAssembly module",
} as const;

/** Decode a caller-selected WebAssembly module; nothing is compiled or run. */
export const createWasmModuleInspector = (): WasmModulePort => {
  const inspect = inspectSingleArtifact<InspectWasmModuleInput>(
    SPEC,
    (selected, input, limitations) =>
      buildWasmModuleReport(selected, input, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectWasmModuleInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> => inspect(input, options),
  };
};
