import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { UNITY_ASSET_VIEWS } from "../domain/unity/unityAssets.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { offlineInspectCommand } from "./offlineInspectCommand.js";

/** Resolve the caller-selected bundle or serialized file through the shared workflow. */
export const registerUnityCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectUnityAssets, {
    description:
      "List objects, asset paths and scripts in a Unity asset bundle or serialized file (level0, *.assets)",
    args: z.object({
      path: z.string().describe("Local asset bundle or serialized file"),
    }),
    options: z.object({
      view: z
        .enum(UNITY_ASSET_VIEWS)
        .optional()
        .describe("objects (default), container or scripts"),
      class_name: z
        .string()
        .optional()
        .describe("Class to keep, such as Texture2D or MonoBehaviour"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, asset path or script filter"),
      offset: z.coerce
        .number()
        .int()
        .optional()
        .describe("Matching entries to skip"),
      limit: z.coerce
        .number()
        .int()
        .optional()
        .describe("Matching entries to return"),
    }),
    run: offlineInspectCommand(
      logger,
      CLI_COMMANDS.inspectUnityAssets,
      async () => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createUnityAssetsService } =
          await import("../composition/unity.js");
        return createUnityAssetsService();
      },
      (args, options) => ({
        path: resolve(args.path),
        view: options.view,
        class_name: options.class_name,
        query: options.query,
        offset: options.offset,
        limit: options.limit,
      }),
    ),
  });
};
