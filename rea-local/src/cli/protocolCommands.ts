import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { PROTOCOL_VIEWS } from "../domain/protocol/protocolFields.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Infer message formats from the caller-selected capture through the shared workflow. */
export const registerProtocolCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inferProtocolFields, {
    description:
      "Infer message formats and fields (lengths, counters, checksums, timestamps, types) of an unknown protocol from a capture or hex messages",
    args: z.object({
      path: z
        .string()
        .describe("Local PCAP/PCAPNG capture, or a text file of hex messages"),
    }),
    options: z.object({
      transport: z
        .enum(["auto", "udp", "tcp"])
        .optional()
        .describe("UDP datagrams, TCP streams, or whichever is present"),
      port: z.coerce
        .number()
        .int()
        .optional()
        .describe("Keep flows with this port"),
      flow: z
        .string()
        .optional()
        .describe("Keep flows whose key contains this text"),
      view: z
        .enum(PROTOCOL_VIEWS)
        .optional()
        .describe("formats (default), fields, messages or flows"),
      format: z.coerce
        .number()
        .int()
        .optional()
        .describe("Format id whose fields or messages to list"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive kind, detail, sample or hex filter"),
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
        // Load the inference only when this command runs, keeping CLI startup light.
        const { createProtocolFieldsService } =
          await import("../composition/protocol.js");
        const service = createProtocolFieldsService();
        try {
          return await logCliCommand(
            logger,
            CLI_COMMANDS.inferProtocolFields,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  transport: options.transport,
                  port: options.port,
                  flow: options.flow,
                  view: options.view,
                  format: options.format,
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
