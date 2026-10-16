import { z } from "incur";
import { resolve } from "node:path";
import { createMinidumpService } from "../composition/minidump.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected dump through the shared workflow. */
export const registerMinidumpCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createMinidumpService();
  cli.command(CLI_COMMANDS.inspectMinidump, {
    description:
      "Explain a Windows, Breakpad or Crashpad minidump: exception, faulting module+offset, threads and modules",
    args: z.object({
      path: z.string().describe("Local minidump (.dmp)"),
    }),
    options: z.object({
      thread_id: z.coerce
        .number()
        .int()
        .optional()
        .describe("Thread to report registers and a stack scan for"),
      stack_scan_limit: z.coerce
        .number()
        .int()
        .optional()
        .describe("Most stack slots to report"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectMinidump,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  thread_id: options.thread_id,
                  stack_scan_limit: options.stack_scan_limit,
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
