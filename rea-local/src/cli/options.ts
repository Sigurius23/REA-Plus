import { isAbsolute } from "node:path";
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
  .optional()
  .describe(
    "Absolute directory that receives container members extracted for member-target opens (path like /path/app.apk#classes.dex); default stages beside the container",
  );

/** Execution settings shared by direct-analysis CLI commands. */
export type directAnalysisSettings = {
  readonly snapshotPath?: string | undefined;
  readonly providerId?: AnalysisProviderSelector | undefined;
  readonly formatHint?: ExecutableFormatHint | undefined;
  readonly stagingDir?: string | undefined;
};

export const directAnalysisOptions = (
  logger: Logger,
  settings: directAnalysisSettings = {},
) => ({
  logger,
  snapshotPath: settings.snapshotPath,
  ...(settings.formatHint === undefined
    ? {}
    : { formatHint: settings.formatHint }),
  ...(settings.providerId === undefined
    ? {}
    : { providerId: settings.providerId }),
  ...(settings.stagingDir === undefined
    ? {}
    : { stagingDir: settings.stagingDir }),
});
