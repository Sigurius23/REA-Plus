import { WasmModuleService } from "../application/wasmmodule/WasmModuleService.js";
import { WasmModuleInspector } from "../wasmmodule/WasmModuleInspector.js";

/** Compose the offline WebAssembly module reader; it needs no tools or configuration. */
export const createWasmModuleService = (): WasmModuleService =>
  new WasmModuleService(new WasmModuleInspector());
