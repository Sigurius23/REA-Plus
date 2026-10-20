import { X64dbgDatabaseService } from "../application/x64dbg/X64dbgDatabaseService.js";
import { X64dbgInspector } from "../x64dbg/X64dbgInspector.js";

/** Compose the offline x64dbg database reader; it needs no tools or configuration. */
export const createX64dbgDatabaseService = (): X64dbgDatabaseService =>
  new X64dbgDatabaseService(new X64dbgInspector());
