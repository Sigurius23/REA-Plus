import { RenpyScriptService } from "../application/renpy/RenpyScriptService.js";
import { createRenpyScriptInspector } from "../renpy/RenpyScriptInspector.js";

/** Compose the offline Ren'Py script reader; it needs no tools or configuration. */
export const createRenpyScriptService = (): RenpyScriptService =>
  new RenpyScriptService(createRenpyScriptInspector());
