import { z } from "incur";
import { resolve } from "node:path";
import {
  createBytePatternService,
  createCheatTableService,
} from "../composition/patterns.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** AOB scanning and Cheat Engine tables through the shared workflows. */
export const registerPatternCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const patterns = createBytePatternService();
  const tables = createCheatTableService();
  cli.command(CLI_COMMANDS.scanBytePatterns, {
    description:
      "Scan a PE, ELF, Mach-O or raw file for AOB signatures such as '48 8B 05 ?? ?? ?? ??'",
    args: z.object({ path: z.string().describe("Local binary") }),
    options: z.object({
      pattern: z.array(z.string()).describe("Byte pattern; repeat for more"),
      scope: z
        .enum(["executable", "all"])
        .optional()
        .describe("Scan code sections (default) or every mapped section"),
      max_matches: z.coerce
        .number()
        .int()
        .optional()
        .describe("Matches to return per pattern; all are counted"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.scanBytePatterns,
            async () => {
              const result = await patterns.scan(
                {
                  path: resolve(args.path),
                  patterns: options.pattern.map((pattern) => ({ pattern })),
                  scope: options.scope,
                  max_matches: options.max_matches,
                },
                { signal },
              );
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
          );
        } finally {
          await patterns.close();
        }
      }),
  });
  cli.command(CLI_COMMANDS.inspectCheatTable, {
    description:
      "Read a Cheat Engine table and optionally re-check its signatures against a module",
    args: z.object({ path: z.string().describe("Local .CT table") }),
    options: z.object({
      binary_path: z
        .string()
        .optional()
        .describe("Module to re-scan AOB signatures and asserts against"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectCheatTable,
            async () => {
              const result = await tables.inspect(
                {
                  path: resolve(args.path),
                  ...(options.binary_path === undefined
                    ? {}
                    : { binary_path: resolve(options.binary_path) }),
                },
                { signal },
              );
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
          );
        } finally {
          await tables.close();
        }
      }),
  });
};
