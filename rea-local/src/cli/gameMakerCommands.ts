import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  GAMEMAKER_RESOURCE_KINDS,
  GAMEMAKER_VIEWS,
} from "../domain/gamemaker/gameMakerData.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected GameMaker data file through the shared workflow. */
export const registerGameMakerCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectGameMakerData, {
    description:
      "Map a GameMaker data.win: chunks, resources, bytecode entries, strings, functions and variables, textures and audio",
    args: z.object({
      path: z
        .string()
        .describe(
          "Local data.win, game.unx, game.droid, game.ios or audiogroupN.dat",
        ),
    }),
    options: z.object({
      view: z
        .enum(GAMEMAKER_VIEWS)
        .optional()
        .describe(
          "chunks (default), resources, code, strings, symbols, textures or audio",
        ),
      kind: z
        .enum(GAMEMAKER_RESOURCE_KINDS)
        .optional()
        .describe(
          "Resource kind for the resources view, such as object or room",
        ),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name or string filter"),
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
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createGameMakerDataService } =
          await import("../composition/gameMaker.js");
        const service = createGameMakerDataService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectGameMakerData,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  kind: options.kind,
                  query: options.query,
                  offset: options.offset,
                  limit: options.limit,
                },
                { signal },
              );
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
          );
        } finally {
          await service.close();
        }
      }),
  });
};
