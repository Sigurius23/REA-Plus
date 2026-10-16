import { UnityAssetsService } from "../application/unity/UnityAssetsService.js";
import { UnityAssetsInspector } from "../unity/UnityAssetsInspector.js";

/** Compose the offline Unity asset reader; it needs no tools or configuration. */
export const createUnityAssetsService = (): UnityAssetsService =>
  new UnityAssetsService(new UnityAssetsInspector());
