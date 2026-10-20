import { Il2CppMetadataService } from "../application/il2cpp/Il2CppMetadataService.js";
import { R2UnityMetadataProvider } from "../il2cpp/R2UnityMetadataProvider.js";

/** Compose the caller-supplied metadata reader without acquisition or import-time I/O. */
export const createIl2CppMetadataService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): Il2CppMetadataService =>
  new Il2CppMetadataService(new R2UnityMetadataProvider(environment));
