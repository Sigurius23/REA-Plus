import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { LuaBytecodePort } from "../application/lua/LuaBytecodePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  luaBytecodeSchema,
  type InspectLuaBytecodeInput,
} from "../domain/lua/luaBytecode.js";
import type { Result } from "../domain/result.js";
import { LuaFormatError, LuaSelectionError } from "./LuaReader.js";
import { buildLuaReport } from "./LuaReport.js";

const OPERATION = "inspect_lua_bytecode";

export const LUA_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "lua-bytecode-reader",
  name: "REA+ Lua bytecode reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads PUC Lua 5.1-5.4 binary chunks and LuaJIT 2.0/2.1 bytecode dumps without loading or running them. Luau (Roblox), Ravi, Pluto and other derived formats are not read.",
  "Opcode names come from the stock opcode tables. A game that reorders opcodes or changes the format (a common protection) decodes with the wrong names, or with UNKNOWN opcodes.",
  "Name hints come from where the code stores each function (a global, a table field or a named local); they are not names the bytecode records.",
  "Stripped chunks have no line numbers, local names or upvalue names. LuaJIT 2.0 dumps are read from LuaJIT's source; only 2.1 was checked against a LuaJIT build.",
];

const SPEC = {
  operation: OPERATION,
  identity: LUA_PROVIDER_IDENTITY,
  maxFileBytes: 512 * 1024 * 1024,
  schema: luaBytecodeSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: LuaSelectionError }],
  formatErrors: [LuaFormatError, RangeError],
  notReadable: "Not readable Lua bytecode",
} as const;

/** Decode a caller-selected Lua chunk; nothing is loaded or run. */
export const createLuaInspector = (): LuaBytecodePort => {
  const inspect = inspectSingleArtifact<InspectLuaBytecodeInput>(
    SPEC,
    (selected, input, limitations) => buildLuaReport(selected, input, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectLuaBytecodeInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> => inspect(input, options),
  };
};
