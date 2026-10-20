import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { WASM_MODULE_VIEWS } from "../domain/wasmmodule/wasmModule.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** A decimal function index stays a number; anything else is a function name. */
const functionSelection = (
  value: string | undefined,
): number | string | undefined =>
  value !== undefined && /^\d+$/u.test(value) ? Number(value) : value;

/** Resolve the caller-selected WebAssembly module through the shared workflow. */
export const registerWasmModuleCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectWasmModule, {
    description:
      "Decode a .wasm module (plain, gzip or Brotli): toolchain, functions with call counts, callers and callees, imports, exports, data strings and sections",
    args: z.object({
      path: z
        .string()
        .describe("Local .wasm, .wasm.gz, .wasm.br or .unityweb module"),
    }),
    options: z.object({
      view: z
        .enum(WASM_MODULE_VIEWS)
        .optional()
        .describe(
          "functions (default), calls, imports, exports, data, strings, sections or custom",
        ),
      function: z
        .string()
        .optional()
        .describe(
          "Function index or name; required by the calls view, a filter for functions",
        ),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive name, module, section or text filter"),
      min_string_length: z.coerce
        .number()
        .int()
        .optional()
        .describe("Shortest printable run in the strings view (default 6)"),
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
        const { createWasmModuleService } =
          await import("../composition/wasmModule.js");
        const service = createWasmModuleService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectWasmModule,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  function: functionSelection(options.function),
                  query: options.query,
                  min_string_length: options.min_string_length,
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
