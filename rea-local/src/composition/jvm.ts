import { JvmArtifactService } from "../application/jvm/JvmArtifactService.js";
import { CfrArtifactProvider } from "../jvm/CfrArtifactProvider.js";

/** Compose the caller-supplied decompiler without acquisition or import-time I/O. */
export const createJvmArtifactService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): JvmArtifactService =>
  new JvmArtifactService(new CfrArtifactProvider(environment));
