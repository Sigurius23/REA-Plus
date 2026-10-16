import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { LuaBytecodePort } from "../application/lua/LuaBytecodePort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  luaBytecodeSchema,
  type InspectLuaBytecodeInput,
} from "../domain/lua/luaBytecode.js";
import { err, ok, type Result } from "../domain/result.js";
import { LuaFormatError, LuaSelectionError } from "./LuaReader.js";
import { buildLuaReport } from "./LuaReport.js";

const OPERATION = "inspect_lua_bytecode";
const MAX_FILE_BYTES = 512 * 1024 * 1024;

export const LUA_PROVIDER_IDENTITY = {
  id: "lua-bytecode-reader",
  name: "REA+ Lua bytecode reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads PUC Lua 5.1-5.4 binary chunks and LuaJIT 2.0/2.1 bytecode dumps without loading or running them. Luau (Roblox), Ravi, Pluto and other derived formats are not read.",
  "Opcode names come from the stock opcode tables. A game that reorders opcodes or changes the format (a common protection) decodes with the wrong names, or with UNKNOWN opcodes.",
  "Name hints come from where the code stores each function (a global, a table field or a named local); they are not names the bytecode records.",
  "Stripped chunks have no line numbers, local names or upvalue names. LuaJIT 2.0 dumps are read from LuaJIT's source; only 2.1 was checked against a LuaJIT build.",
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
  if (cause instanceof LuaSelectionError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof LuaFormatError || cause instanceof RangeError
          ? `Not readable Lua bytecode: ${reason}`
          : reason,
    },
  ]);
};

/** Decode a caller-selected Lua chunk; nothing is loaded or run. */
export class LuaInspector implements LuaBytecodePort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectLuaBytecodeInput,
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
      const report = luaBytecodeSchema.parse(
        buildLuaReport(selected, input, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, LUA_PROVIDER_IDENTITY, {
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
