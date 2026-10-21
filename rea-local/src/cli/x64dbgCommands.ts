import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { X64DBG_VIEWS } from "../domain/x64dbg/x64dbgDatabase.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { offlineInspectCommand } from "./offlineInspectCommand.js";

/** Resolve the caller-selected x64dbg database through the shared workflow. */
export const registerX64dbgCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectX64dbgDatabase, {
    description:
      "Read an x64dbg .dd32/.dd64 database: labels, comments, bookmarks, functions, breakpoints, xrefs and watches, optionally placed in the module file",
    args: z.object({
      path: z.string().describe("Local .dd32 or .dd64 database"),
    }),
    options: z.object({
      view: z
        .enum(X64DBG_VIEWS)
        .optional()
        .describe(
          "labels (default), comments, bookmarks, functions, arguments, loops, breakpoints, xrefs or watch",
        ),
      module: z
        .string()
        .optional()
        .describe("Keep entries of this module, such as game.exe"),
      module_path: z
        .string()
        .optional()
        .describe(
          "Module binary to place addresses in and check breakpoint bytes against",
        ),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive text, name or condition filter"),
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
      CLI_COMMANDS.inspectX64dbgDatabase,
      async () => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createX64dbgDatabaseService } =
          await import("../composition/x64dbg.js");
        return createX64dbgDatabaseService();
      },
      (args, options) => ({
        path: resolve(args.path),
        view: options.view,
        module: options.module,
        module_path:
          options.module_path === undefined
            ? undefined
            : resolve(options.module_path),
        query: options.query,
        offset: options.offset,
        limit: options.limit,
      }),
    ),
  });
};
