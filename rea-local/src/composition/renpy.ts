import { RenpyScriptService } from "../application/renpy/RenpyScriptService.js";
import { RenpyScriptInspector } from "../renpy/RenpyScriptInspector.js";

/** Compose the offline Ren'Py script reader; it needs no tools or configuration. */
export const createRenpyScriptService = (): RenpyScriptService =>
  new RenpyScriptService(new RenpyScriptInspector());
