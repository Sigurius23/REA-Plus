import { LuaBytecodeService } from "../application/lua/LuaBytecodeService.js";
import { LuaInspector } from "../lua/LuaInspector.js";

/** Compose the offline Lua bytecode reader; it needs no tools or configuration. */
export const createLuaBytecodeService = (): LuaBytecodeService =>
  new LuaBytecodeService(new LuaInspector());
