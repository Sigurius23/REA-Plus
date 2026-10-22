import { isAbsolute } from "node:path";
import { z } from "incur";
import {
  executableFormatHintSchema,
  type ExecutableFormatHint,
} from "../domain/dosCom.js";
import { analysisProviderSelectorSchema } from "../contracts/providerSelection.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";
import type { Logger } from "pino";
import { localPathStringSchema } from "../domain/localPath.js";

export const providerSelectionOption = analysisProviderSelectorSchema
  .optional()
  .describe(
    "Bind deep analysis to a provider ID or use deterministic auto selection",
  );

/** Explicit interpretation for headerless native executable formats. */
export const formatSelectionOption = executableFormatHintSchema
  .optional()
  .describe("Explicit headerless DOS COM interpretation");

/** Staging root for container-member opens like `/path/app.apk#classes.dex`. */
export const stagingDirSelectionOption = localPathStringSchema
  .refine(isAbsolute, {
    message: "staging-dir must be an absolute local directory path",
  })
  .describe(
    "Absolute directory that receives container members extracted for member-target opens (path like /path/app.apk#classes.dex); default stages beside the container",
  )
  .optional();

export const directAnalysisOptions = (
  logger: Logger,
  snapshotPath: string | undefined,
  providerId: AnalysisProviderSelector | undefined,
  formatHint?: ExecutableFormatHint,
  stagingDir?: string,
) => ({
  logger,
  snapshotPath,
  ...(formatHint === undefined ? {} : { formatHint }),
  ...(providerId === undefined ? {} : { providerId }),
  ...(stagingDir === undefined ? {} : { stagingDir }),
});
