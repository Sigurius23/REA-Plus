import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected logs through the shared workflow. */
export const registerCoverageCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectCoverageLog, {
    description:
      "Summarize a drcov coverage log, list a module's executed blocks, or diff against a baseline run",
    args: z.object({
      path: z.string().describe("Local drcov log"),
    }),
    options: z.object({
      baseline_path: z
        .string()
        .optional()
        .describe("drcov log of a run without the behavior of interest"),
      module: z
        .string()
        .optional()
        .describe("Module path or file name whose blocks to list"),
      offset: z.coerce.number().int().optional().describe("Blocks to skip"),
      limit: z.coerce.number().int().optional().describe("Blocks to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createCoverageLogService } =
          await import("../composition/coverage.js");
        const service = createCoverageLogService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectCoverageLog,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  ...(options.baseline_path === undefined
                    ? {}
                    : { baseline_path: resolve(options.baseline_path) }),
                  module: options.module,
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
