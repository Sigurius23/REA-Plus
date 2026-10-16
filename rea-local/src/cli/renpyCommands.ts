import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { RENPY_SCRIPT_VIEWS } from "../domain/renpy/renpyScript.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected .rpyc through the shared workflow. */
export const registerRenpyCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectRenpyScript, {
    description:
      "Map a compiled Ren'Py script: labels, dialogue with translation identifiers, menus, definitions and translations",
    args: z.object({
      path: z.string().describe("Local .rpyc file"),
    }),
    options: z.object({
      view: z
        .enum(RENPY_SCRIPT_VIEWS)
        .optional()
        .describe(
          "labels (default), dialogue, menus, definitions or translations",
        ),
      label: z
        .string()
        .optional()
        .describe("Keep dialogue and menus under this label"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive text, speaker or name filter"),
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
        const { createRenpyScriptService } =
          await import("../composition/renpy.js");
        const service = createRenpyScriptService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectRenpyScript,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  label: options.label,
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
