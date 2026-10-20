import { GameMakerDataService } from "../application/gamemaker/GameMakerDataService.js";
import { GameMakerInspector } from "../gamemaker/GameMakerInspector.js";

/** Compose the offline GameMaker data reader; it needs no tools or configuration. */
export const createGameMakerDataService = (): GameMakerDataService =>
  new GameMakerDataService(new GameMakerInspector());
