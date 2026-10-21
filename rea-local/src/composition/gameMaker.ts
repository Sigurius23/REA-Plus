import { GameMakerDataService } from "../application/gamemaker/GameMakerDataService.js";
import { createGameMakerInspector } from "../gamemaker/GameMakerInspector.js";

/** Compose the offline GameMaker data reader; it needs no tools or configuration. */
export const createGameMakerDataService = (): GameMakerDataService =>
  new GameMakerDataService(createGameMakerInspector());
