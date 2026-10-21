import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import {
  IDENTIFICATION_STATUSES,
  LIBRARY_VIEWS,
} from "../domain/libid/libraryIdentification.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { offlineInspectCommand } from "./offlineInspectCommand.js";

/** Name statically linked library functions in a binary through the shared workflow. */
export const registerLibraryIdentificationCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.identifyLibraryFunctions, {
    description:
      "Name statically linked library functions in a stripped ELF or PE binary from the static libraries or objects it may have linked",
    args: z.object({
      path: z.string().describe("Local ELF or PE executable or library"),
    }),
    options: z.object({
      library: z
        .array(z.string())
        .describe("Static library (.a, .lib) or object file; repeat for more"),
      minBytes: z.coerce
        .number()
        .int()
        .optional()
        .describe("Fewest fixed bytes for a signature (default 16)"),
      includeLocal: z
        .boolean()
        .optional()
        .describe("Sign static functions too (default true)"),
      view: z
        .enum(LIBRARY_VIEWS)
        .optional()
        .describe("summary (default) or functions"),
      status: z
        .enum(IDENTIFICATION_STATUSES)
        .optional()
        .describe("unique, resolved or ambiguous"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, member or address filter"),
      offset: z.coerce.number().int().optional().describe("Rows to skip"),
      limit: z.coerce.number().int().optional().describe("Rows to return"),
    }),
    run: offlineInspectCommand(
      logger,
      CLI_COMMANDS.identifyLibraryFunctions,
      async () => {
        // Load the identifier only when this command runs, keeping CLI startup light.
        const { createLibraryIdentificationService } =
          await import("../composition/libraryIdentification.js");
        return createLibraryIdentificationService();
      },
      (args, options) => ({
        path: resolve(args.path),
        libraries: options.library.map((library) => resolve(library)),
        min_bytes: options.minBytes,
        include_local: options.includeLocal,
        view: options.view,
        status: options.status,
        query: options.query,
        offset: options.offset,
        limit: options.limit,
      }),
    ),
  });
};
