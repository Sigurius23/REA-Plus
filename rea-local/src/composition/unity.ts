import { UnityAssetsService } from "../application/unity/UnityAssetsService.js";
import { createUnityAssetsInspector } from "../unity/UnityAssetsInspector.js";

/** Compose the offline Unity asset reader; it needs no tools or configuration. */
export const createUnityAssetsService = (): UnityAssetsService =>
  new UnityAssetsService(createUnityAssetsInspector());
