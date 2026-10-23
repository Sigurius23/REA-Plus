import { z } from "incur";
import { stat } from "node:fs/promises";
import { resolve } from "node:path";

import { resolveCliAnalysisSelector } from "./analysisSelector.js";
import type { DirectAnalysis } from "../composition/directAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { ExecutableFormatHint } from "../domain/dosCom.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";
import {
  directAnalysisOptions,
  formatSelectionOption,
  providerSelectionOption,
  stagingDirSelectionOption,
} from "./options.js";
import type { CliInstance } from "./types.js";
import { runCliJavaScriptApplicationAnalysis } from "./javascriptApplicationAnalysis.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { javascriptApplicationOptions } from "../cliObservationOptions.js";

const snapshotOption = z
  .string()
  .min(1)
  .optional()
  .describe("Load and update a local analysis snapshot");

const procedureOption = z
  .string()
  .min(1)
  .optional()
  .describe(
    "Procedure name or address; use --procedure=<value> for leading dashes",
  );

/** Options shared by every provider-neutral direct-analysis command. */
const standardAnalysisOptions = {
  snapshot: snapshotOption,
  "target-format": formatSelectionOption,
  "staging-dir": stagingDirSelectionOption,
  provider: providerSelectionOption,
};

/** Route parsed standard options into direct-analysis execution options. */
const directOptions = (
  logger: Logger,
  options: {
    readonly snapshot?: string | undefined;
    readonly "target-format"?: ExecutableFormatHint | undefined;
    readonly provider?: AnalysisProviderSelector | undefined;
    readonly "staging-dir"?: string | undefined;
  },
): ReturnType<typeof directAnalysisOptions> =>
  directAnalysisOptions(logger, {
    snapshotPath: options.snapshot,
    providerId: options.provider,
    formatHint: options["target-format"],
    stagingDir: options["staging-dir"],
  });

/** Resolved via --procedure for the procedure selector commands. */
const registerProcedureSelectorCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
  registration: {
    readonly command: string;
    readonly description: string;
    readonly operation:
      | "procedure_pseudo_code"
      | "analyze_function"
      | "read_function_instructions";
  },
): void => {
  cli.command(registration.command, {
    description: registration.description,
    args: z.object({
      path: z.string().describe("App or program path"),
      address: z
        .string()
        .min(1)
        .optional()
        .describe("Procedure name or address"),
    }),
    options: z.object({
      procedure: procedureOption,
      ...standardAnalysisOptions,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, registration.command, () =>
        runDirectAnalysis(
          args.path,
          registration.operation,
          {
            procedure: resolveCliAnalysisSelector(
              args.address,
              options.procedure,
              "procedure",
              registration.operation,
            ),
          },
          directOptions(logger, options),
        ),
      ),
  });
};

/** Register provider-neutral binary overview and procedure CLI commands. */
export const registerCoreBinaryCommands = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  registerOverviewCommands(cli, logger, runDirectAnalysis);
  registerProcedureSelectorCommand(cli, logger, runDirectAnalysis, {
    command: CLI_COMMANDS.decompile,
    description: "Read one part of an app as code",
    operation: "procedure_pseudo_code",
  });
  registerProcedureSelectorCommand(cli, logger, runDirectAnalysis, {
    command: CLI_COMMANDS.function,
    description: "Analyze one complete function with evidence",
    operation: "analyze_function",
  });
  registerProcedureSelectorCommand(cli, logger, runDirectAnalysis, {
    command: CLI_COMMANDS.instructions,
    description: "Read every raw instruction without decompiling",
    operation: "read_function_instructions",
  });
  registerSearchCommand(cli, logger, runDirectAnalysis);
  registerXrefsCommand(cli, logger, runDirectAnalysis);
  registerTraceCommand(cli, logger, runDirectAnalysis);
};

const registerOverviewCommands = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  const overviewOptions = z.object({ ...standardAnalysisOptions });
  cli.command(CLI_COMMANDS.analyze, {
    description: "Get an overview of an app",
    args: z.object({
      path: z.string().describe("App, program, or analysis database path"),
    }),
    options: overviewOptions.extend({
      integrityPolicy: javascriptApplicationOptions.shape.integrityPolicy,
    }),
    run: async ({ args, options }) => {
      // Route JavaScript targets exactly like analyze-javascript-application,
      // including typed cancellation; cancellation wraps logging so its exit
      // code is not replaced by the logged failure status.
      if (await routesToJavaScriptAnalysis(args.path, options))
        return withCommandCancellation((signal) =>
          logCliCommand(logger, "analyze", () =>
            runCliJavaScriptApplicationAnalysis(
              {
                input_path: resolve(args.path),
                integrity_policy: options.integrityPolicy,
              },
              signal,
            ),
          ),
        );
      return logCliCommand(logger, "analyze", () =>
        runDirectAnalysis(
          args.path,
          "binary_overview",
          {},
          directOptions(logger, options),
        ),
      );
    },
  });
  cli.command(CLI_COMMANDS.inspect, {
    description: "Inspect an app overview with evidence",
    args: z.object({
      path: z.string().describe("App, program, or analysis database path"),
    }),
    options: overviewOptions,
    run: ({ args, options }) =>
      logCliCommand(logger, "inspect", () =>
        runDirectAnalysis(
          args.path,
          "binary_overview",
          {},
          directOptions(logger, options),
        ),
      ),
  });
};

/** Select static JavaScript analysis only when no binary-analysis option applies. */
const routesToJavaScriptAnalysis = async (
  path: string,
  options: {
    readonly snapshot?: string | undefined;
    readonly "target-format"?: "dos-com" | undefined;
    readonly provider?: string | undefined;
  },
): Promise<boolean> =>
  options.provider === undefined &&
  options.snapshot === undefined &&
  options["target-format"] === undefined &&
  (await isJavaScriptApplicationPath(path));

const isJavaScriptApplicationPath = async (path: string): Promise<boolean> => {
  const lower = path.toLowerCase();
  if (lower.endsWith(".asar")) return true;
  if (lower.endsWith(".app")) return false;
  try {
    return (await stat(path)).isDirectory();
  } catch (cause: unknown) {
    // A missing or unreadable path is not a JavaScript application directory;
    // the caller falls through to direct binary analysis instead.
    void cause;
    return false;
  }
};

const registerXrefsCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.xrefs, {
    description: "List bounded references to an analyzed address",
    args: z.object({
      path: z.string().describe("App or program path"),
      address: z.string().min(1).optional().describe("Address or symbol name"),
    }),
    options: z.object({
      address: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Address or symbol name; use --address=<value> for leading dashes",
        ),
      ...standardAnalysisOptions,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "xrefs", () =>
        runDirectAnalysis(
          args.path,
          "xrefs",
          {
            address: resolveCliAnalysisSelector(
              args.address,
              options.address,
              "address",
              "xrefs",
            ),
          },
          directOptions(logger, options),
        ),
      ),
  });
};

const registerTraceCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.trace, {
    description: "Trace a literal feature through analyzed references",
    args: z.object({
      path: z.string().describe("App or program path"),
      query: z.string().min(1).optional().describe("Literal feature query"),
    }),
    options: z.object({
      query: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Complete literal feature query; use --query=<value> for leading dashes",
        ),
      caseSensitive: z
        .boolean()
        .default(false)
        .describe("Match the query with exact letter case"),
      ...standardAnalysisOptions,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "trace", () =>
        runDirectAnalysis(
          args.path,
          "trace_feature",
          {
            query: resolveCliAnalysisSelector(
              args.query,
              options.query,
              "query",
              "trace_feature",
            ),
            case_sensitive: options.caseSensitive,
          },
          directOptions(logger, options),
        ),
      ),
  });
};

const registerSearchCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.search, {
    description: "Search every analyzed string or procedure name",
    args: z.object({
      path: z.string().describe("App or program path"),
      pattern: z
        .string()
        .min(1)
        .optional()
        .describe("Literal text or regex pattern"),
    }),
    options: z.object({
      pattern: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Complete literal text or regex pattern; use --pattern=<value> for leading dashes",
        ),
      kind: z
        .enum(["strings", "procedures"])
        .default("strings")
        .describe("Analyzed item kind to search"),
      mode: z
        .enum(["literal", "regex"])
        .default("literal")
        .describe("Interpret the pattern as literal text or a regex"),
      caseSensitive: z
        .boolean()
        .default(false)
        .describe("Match the pattern with exact letter case"),
      ...standardAnalysisOptions,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "search", () =>
        runDirectAnalysis(
          args.path,
          options.kind === "strings" ? "search_strings" : "search_procedures",
          {
            pattern: resolveCliAnalysisSelector(
              args.pattern,
              options.pattern,
              "pattern",
              options.kind === "strings"
                ? "search_strings"
                : "search_procedures",
            ),
            mode: options.mode,
            case_sensitive: options.caseSensitive,
          },
          directOptions(logger, options),
        ),
      ),
  });
};
