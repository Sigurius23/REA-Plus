import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { GODOT_VIEWS } from "../domain/godot/godotFile.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected Godot file or pack entry through the shared workflow. */
export const registerGodotCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.inspectGodotFile, {
    description:
      "Decode Godot binary resources and scenes, compiled GDScript (.gdc/.gde) and store_var saves, from a file or an entry of a .pck",
    args: z.object({
      path: z
        .string()
        .describe(
          "Local .res/.scn/.gdc/.gde file, a save, or a .pck / game executable with entry",
        ),
    }),
    options: z.object({
      entry: z
        .string()
        .optional()
        .describe(
          "Path inside the pack, e.g. res://player.gd (follows .remap)",
        ),
      view: z
        .enum(GODOT_VIEWS)
        .optional()
        .describe(
          "resources, properties, nodes, connections, source, tokens or values",
        ),
      resource: z
        .string()
        .optional()
        .describe("Sub-resource id (or main) whose properties to list"),
      node: z.string().optional().describe("Scene node path (. for the root)"),
      key_env: z
        .string()
        .optional()
        .describe("Environment variable holding a 64-hex-digit AES-256 key"),
      password_env: z
        .string()
        .optional()
        .describe(
          "Environment variable holding an open_encrypted_with_pass password",
        ),
      engine: z
        .enum(["auto", "3", "4"])
        .optional()
        .describe("Godot major version of store_var data"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, type, path, value or source filter"),
      offset: z.coerce
        .number()
        .int()
        .optional()
        .describe("Matching rows to skip"),
      limit: z.coerce
        .number()
        .int()
        .optional()
        .describe("Matching rows to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createGodotFileService } =
          await import("../composition/godot.js");
        const service = createGodotFileService(environment);
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectGodotFile,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  entry: options.entry,
                  view: options.view,
                  resource: options.resource,
                  node: options.node,
                  key_env: options.key_env,
                  password_env: options.password_env,
                  engine: options.engine,
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
