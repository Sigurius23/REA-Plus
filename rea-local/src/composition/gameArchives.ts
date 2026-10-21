import { GameArchiveService } from "../application/gamearchives/GameArchiveService.js";
import { createGameArchiveInspector } from "../gamearchives/GameArchiveInspector.js";

/** Compose the offline game archive reader; it needs no tools or configuration. */
export const createGameArchiveService = (): GameArchiveService =>
  new GameArchiveService(createGameArchiveInspector());
