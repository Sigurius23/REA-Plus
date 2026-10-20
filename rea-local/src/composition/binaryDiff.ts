import { BinaryDiffService } from "../application/bindiff/BinaryDiffService.js";
import { BinaryDiffInspector } from "../bindiff/BinaryDiffInspector.js";
import { parseConfig } from "../config/parseConfig.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";

/**
 * Compose binary diffing over the same provider selection as `rea analyze`;
 * each build gets its own session, created only when a diff runs.
 */
export const createBinaryDiffService = (
  selectedEnvironment: Readonly<NodeJS.ProcessEnv> = process.env,
): BinaryDiffService => {
  const environment = snapshotEnvironment(selectedEnvironment);
  return new BinaryDiffService(
    new BinaryDiffInspector(async () => {
      const config = parseConfig(environment);
      if (!config.ok) return config;
      const { createBinarySession } = await import("./binary.js");
      return ok(createBinarySession(config.value, silentLogger, environment));
    }),
  );
};
