import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected session through the shared workflow. */
export const registerLogicCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.inspectLogicCapture, {
    description:
      "Summarize a sigrok logic capture and optionally decode protocols with sigrok-cli",
    args: z.object({
      path: z.string().describe("Local sigrok session (.sr)"),
    }),
    options: z.object({
      decoders_json: z
        .string()
        .optional()
        .describe(
          'Decoder stack as JSON, e.g. [{"id":"uart","channels":{"rx":"D0"},"options":{"baudrate":115200}}]',
        ),
      annotations: z
        .array(z.string())
        .optional()
        .describe("Annotation classes of the top decoder"),
      annotation_limit: z.coerce
        .number()
        .int()
        .optional()
        .describe("Most annotations to return per class"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createLogicCaptureService } =
          await import("../composition/logic.js");
        const service = createLogicCaptureService(environment);
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectLogicCapture,
            async () => {
              const decoders =
                options.decoders_json === undefined
                  ? undefined
                  : (JSON.parse(options.decoders_json) as unknown);
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  decoders,
                  annotations: options.annotations,
                  annotation_limit: options.annotation_limit,
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
