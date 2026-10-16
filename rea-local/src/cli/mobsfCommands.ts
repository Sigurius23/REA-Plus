import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { MOBSF_SEVERITIES, MOBSF_VIEWS } from "../domain/mobsf/mobsfReport.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected MobSF report through the shared workflow. */
export const registerMobsfCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectMobsfReport, {
    description:
      "Read a MobSF JSON report: app identity, score, findings with CWE/MASVS and file locations, permissions, components, native libraries, endpoints, secrets, trackers and APKiD protections",
    args: z.object({
      path: z.string().describe("Local MobSF static-analysis JSON report"),
    }),
    options: z.object({
      view: z
        .enum(MOBSF_VIEWS)
        .optional()
        .describe(
          "findings (default), locations, permissions, components, binaries, apis, endpoints, domains, secrets, trackers, protections or files",
        ),
      severity: z
        .enum(MOBSF_SEVERITIES)
        .optional()
        .describe("Keep findings of this severity"),
      section: z
        .string()
        .optional()
        .describe(
          "Keep findings or locations of one section, such as manifest, code or hardening",
        ),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive title, rule, name, path or value filter"),
      app_path: z
        .string()
        .optional()
        .describe("APK, AAB or IPA to check against the report's SHA-256"),
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
        const { createMobsfReportService } =
          await import("../composition/mobsf.js");
        const service = createMobsfReportService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inspectMobsfReport,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  view: options.view,
                  severity: options.severity,
                  section: options.section,
                  query: options.query,
                  app_path:
                    options.app_path === undefined
                      ? undefined
                      : resolve(options.app_path),
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
