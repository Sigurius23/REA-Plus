import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { DIFF_STATUSES, DIFF_VIEWS } from "../domain/bindiff/binaryDiff.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Diff two builds function by function through the configured analysis provider. */
export const registerBinaryDiffCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.diffBinaries, {
    description:
      "Diff two builds of a native binary function by function: matched, changed, added and removed functions, and one function's instruction diff",
    args: z.object({
      left: z.string().describe("Older build"),
      right: z.string().describe("Newer build"),
    }),
    options: z.object({
      view: z
        .enum(DIFF_VIEWS)
        .optional()
        .describe("summary (default), functions, unmatched or function"),
      status: z
        .enum(DIFF_STATUSES)
        .optional()
        .describe("identical or changed pairs; removed or added functions"),
      function: z
        .string()
        .optional()
        .describe("Address or name for the function view"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name or address filter"),
      names: z
        .boolean()
        .optional()
        .describe("Match same-named functions first (default true)"),
      threshold: z.coerce
        .number()
        .optional()
        .describe("Lowest similarity for a fuzzy match (default 0.5)"),
      maxFunctions: z.coerce
        .number()
        .int()
        .optional()
        .describe("Functions analyzed per build (default 3000)"),
      offset: z.coerce.number().int().optional().describe("Rows to skip"),
      limit: z.coerce.number().int().optional().describe("Rows to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the provider wiring only when this command runs, keeping CLI startup light.
        const { createBinaryDiffService } =
          await import("../composition/binaryDiff.js");
        const service = createBinaryDiffService(environment);
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.diffBinaries,
            async () => {
              const result = await service.inspect(
                {
                  left: resolve(args.left),
                  right: resolve(args.right),
                  view: options.view,
                  status: options.status,
                  function: options.function,
                  query: options.query,
                  names: options.names,
                  threshold: options.threshold,
                  max_functions: options.maxFunctions,
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
