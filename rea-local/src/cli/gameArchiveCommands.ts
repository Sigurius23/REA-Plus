import { z } from "incur";
import { resolve } from "node:path";
import { createGameArchiveService } from "../composition/gameArchives.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected archive through the shared workflow. */
export const registerGameArchiveCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createGameArchiveService();
  cli.command(CLI_COMMANDS.inspectGameArchive, {
    description:
      "List a Godot .pck, Ren'Py .rpa, Valve .vpk or Doom WAD, and preview one entry",
    args: z.object({
      path: z.string().describe("Local archive or game executable"),
    }),
    options: z.object({
      query: z
        .string()
        .optional()
        .describe("Case-insensitive substring of entry paths"),
      extension: z
        .string()
        .optional()
        .describe("Keep entries with this extension, such as gd or rpyc"),
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
      entry: z.string().optional().describe("Exact entry path to preview"),
      preview_bytes: z.coerce
        .number()
        .int()
        .optional()
        .describe("Bytes of the entry to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectGameArchive,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  query: options.query,
                  extension: options.extension,
                  offset: options.offset,
                  limit: options.limit,
                  entry: options.entry,
                  preview_bytes: options.preview_bytes,
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
