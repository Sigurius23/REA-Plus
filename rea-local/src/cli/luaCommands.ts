import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { LUA_VIEWS } from "../domain/lua/luaBytecode.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected Lua chunk through the shared workflow. */
export const registerLuaCommands = (cli: CliInstance, logger: Logger): void => {
  cli.command(CLI_COMMANDS.inspectLuaBytecode, {
    description:
      "Decode compiled Lua (luac 5.1-5.4, LuaJIT): functions with name hints, instruction listings, constants, locals and upvalues, or chunks embedded in a file",
    args: z.object({
      path: z
        .string()
        .describe(
          "Local .luac/.lua bytecode, LuaJIT dump, or a file with chunks inside",
        ),
    }),
    options: z.object({
      view: z
        .enum(LUA_VIEWS)
        .optional()
        .describe(
          "functions (default), instructions, constants, locals, upvalues or chunks",
        ),
      function: z
        .string()
        .optional()
        .describe("Function id such as 0 or 0/2/1"),
      chunk_offset: z.coerce
        .number()
        .int()
        .optional()
        .describe("Byte offset of the chunk inside the file"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, opcode, operand or constant filter"),
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
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        // Load the reader only when this command runs, keeping CLI startup light.
        const { createLuaBytecodeService } =
          await import("../composition/lua.js");
        const service = createLuaBytecodeService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectLuaBytecode,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  function: options.function,
                  chunk_offset: options.chunk_offset,
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
