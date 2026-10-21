import { LuaBytecodeService } from "../application/lua/LuaBytecodeService.js";
import { createLuaInspector } from "../lua/LuaInspector.js";

/** Compose the offline Lua bytecode reader; it needs no tools or configuration. */
export const createLuaBytecodeService = (): LuaBytecodeService =>
  new LuaBytecodeService(createLuaInspector());
