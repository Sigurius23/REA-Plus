import {
  inspectLuaBytecodeInputSchema,
  luaBytecodeSchema,
} from "../../domain/lua/luaBytecode.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free Lua bytecode reader with CLI/MCP parity; chunks are never loaded or run. */
export const LUA_TOOL_CONTRACTS = [
  {
    name: "inspect_lua_bytecode",
    ...toolContractMetadata("inspect_lua_bytecode"),
    kind: "artifact-provider",
    description:
      "Decode compiled Lua that games and mods ship (PUC Lua 5.1, 5.2, 5.3 and 5.4 binary chunks from luac or string.dump, and LuaJIT 2.0/2.1 bytecode from luajit -b) without loading or running it, and return Evidence of the chunk: dialect, byte order, type sizes, chunk name and whether debug info was stripped; counts; then one paged view. functions lists the function tree with name hints recovered from where the code stores each function, defining lines, parameters, stack size and sizes; instructions is the listing with opcodes and operands as luac -l or luajit -bl print them, source lines, referenced constants and upvalues, and jump targets; constants, locals and upvalues list the rest. chunks scans any file, such as a game archive or save, for embedded chunks and reads each one; chunk_offset then selects one.",
    inputSchema: inspectLuaBytecodeInputSchema,
    outputSchema: evidenceResultOf(luaBytecodeSchema),
    examples: [
      {
        title: "List the functions of a compiled game script",
        input: { path: "/games/mod/scripts/main.luac" },
      },
      {
        title: "Read one function's instructions",
        input: {
          path: "/games/mod/scripts/main.luac",
          view: "instructions",
          function: "0/3",
        },
      },
      {
        title: "Find Lua chunks embedded in a data file",
        input: { path: "/games/game/data.pak", view: "chunks" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
