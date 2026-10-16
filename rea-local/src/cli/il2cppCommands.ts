import { z } from "incur";
import { resolve } from "node:path";
import { createIl2CppMetadataService } from "../composition/il2cpp.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { IL2CPP_METADATA_VIEWS } from "../domain/il2cpp/il2cppMetadata.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected metadata and binary through the shared workflow. */
export const registerIl2CppCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = createIl2CppMetadataService(environment);
  cli.command(CLI_COMMANDS.inspectIl2CppMetadata, {
    description:
      "Page classes, string literals, interop or assemblies from Unity IL2CPP metadata with r2unity",
    args: z.object({
      metadata_path: z.string().describe("Local global-metadata.dat"),
    }),
    options: z.object({
      binary_path: z
        .string()
        .optional()
        .describe("Native IL2CPP binary for method addresses"),
      code_registration: z
        .string()
        .optional()
        .describe("Il2CppCodeRegistration address for stripped binaries"),
      view: z.enum(IL2CPP_METADATA_VIEWS).optional().describe("View to page"),
      query: z.string().optional().describe("Case-insensitive name filter"),
      offset: z.coerce.number().int().optional().describe("Matches to skip"),
      limit: z.coerce.number().int().optional().describe("Matches to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectIl2CppMetadata,
            async () => {
              const result = await service.inspect(
                {
                  metadata_path: resolve(args.metadata_path),
                  ...(options.binary_path === undefined
                    ? {}
                    : { binary_path: resolve(options.binary_path) }),
                  code_registration: options.code_registration,
                  view: options.view,
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
