import { z } from "incur";
import { resolve } from "node:path";
import { createRpgMakerProjectService } from "../composition/rpgMaker.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  RPG_MAKER_TABLES,
  RPG_MAKER_VIEWS,
} from "../domain/rpgmaker/rpgMakerProject.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected game folder through the shared workflow. */
export const registerRpgMakerCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createRpgMakerProjectService();
  cli.command(CLI_COMMANDS.inspectRpgMakerProject, {
    description:
      "Map an RPG Maker MV/MZ game: maps, dialogue, switches, database, plugins, encrypted assets and saves",
    args: z.object({
      path: z.string().describe("Game or project folder (holding data/ or www/data/)"),
    }),
    options: z.object({
      view: z
        .enum(RPG_MAKER_VIEWS)
        .optional()
        .describe(
          "maps (default), dialogue, switches, database, plugins, assets or saves",
        ),
      map: z.coerce
        .number()
        .int()
        .optional()
        .describe("Keep maps, dialogue and switch sites of this map id"),
      table: z
        .enum(RPG_MAKER_TABLES)
        .optional()
        .describe("Database table for the database view"),
      asset: z
        .string()
        .optional()
        .describe("Asset path relative to the game folder to decrypt fully"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, text, note or path filter"),
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
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectRpgMakerProject,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  map: options.map,
                  table: options.table,
                  asset: options.asset,
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
