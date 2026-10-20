import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { WasmModulePort } from "../application/wasmmodule/WasmModulePort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  wasmModuleSchema,
  type InspectWasmModuleInput,
} from "../domain/wasmmodule/wasmModule.js";
import { buildWasmModuleReport } from "./WasmModuleReport.js";
import { WasmFormatError, WasmSelectionError } from "./WasmReader.js";

const OPERATION = "inspect_wasm_module";
const MAX_FILE_BYTES = 512 * 1024 * 1024;

export const WASM_MODULE_PROVIDER_IDENTITY = {
  id: "wasm-module-reader",
  name: "REA+ WebAssembly module reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads WebAssembly core modules (version 1), plain or gzip/Brotli-compressed, without WABT, Binaryen or a JavaScript engine; nothing is compiled or run. Component-model binaries are refused.",
  "Direct calls come from call and return_call; call_indirect and call_ref targets depend on runtime tables and are counted, not resolved.",
  "Instruction decoding covers the core, SIMD, threads, bulk memory, reference types, exception handling, tail calls and GC proposals; a body with any other opcode is marked decoded: false.",
  "Function names come from the name section when the build kept it; otherwise from exports and imports. Strings are printable ASCII runs in data segments, not proven string values.",
  "Detected toolchains are indicators: import and export naming conventions, producers entries and engine marker strings in data (UnityEngine., il2cpp, Godot Engine, /rustc/, bevy_), not proof of how the module was built.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  if (cause instanceof WasmSelectionError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["function"], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof WasmFormatError || cause instanceof RangeError
          ? `Not a readable WebAssembly module: ${reason}`
          : reason,
    },
  ]);
};

/** Decode a caller-selected WebAssembly module; nothing is compiled or run. */
export class WasmModuleInspector implements WasmModulePort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectWasmModuleInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_FILE_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = wasmModuleSchema.parse(
        buildWasmModuleReport(selected, input, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, WASM_MODULE_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
