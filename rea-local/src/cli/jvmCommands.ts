import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected artifact through the shared workflow. */
export const registerJvmCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.inspectJvmArtifact, {
    description:
      "List a local JAR or .class file and decompile selected classes with CFR",
    args: z.object({
      path: z.string().describe("Local JAR or .class file"),
    }),
    options: z.object({
      classes: z
        .array(z.string())
        .optional()
        .describe("Binary class names to decompile, such as com.example.Main"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createJvmArtifactService } =
          await import("../composition/jvm.js");
        const service = createJvmArtifactService(environment);
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectJvmArtifact,
            async () => {
              const result = await service.inspect(
                { path: resolve(args.path), classes: options.classes },
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
