import { RpgMakerProjectService } from "../application/rpgmaker/RpgMakerProjectService.js";
import { RpgMakerInspector } from "../rpgmaker/RpgMakerInspector.js";

/** Compose the offline RPG Maker MV/MZ reader; it needs no tools or configuration. */
export const createRpgMakerProjectService = (): RpgMakerProjectService =>
  new RpgMakerProjectService(new RpgMakerInspector());
