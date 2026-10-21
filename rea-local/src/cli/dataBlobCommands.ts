import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import {
  BLOB_DECODERS,
  BLOB_LAYERS,
  BLOB_VIEWS,
} from "../domain/blob/dataBlob.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { offlineInspectCommand } from "./offlineInspectCommand.js";

/** Comma-separated layer names, in the order to remove them. */
const layerList = (value: string | undefined) =>
  value === undefined
    ? undefined
    : value
        .split(",")
        .map((layer) => layer.trim())
        .filter((layer) => layer !== "");

/** Resolve the caller-selected blob through the shared workflow. */
export const registerDataBlobCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectDataBlob, {
    description:
      "Decode a save, cache or packet payload without a schema: base64/hex/gzip/zlib/zstd/LZ4 layers, then JSON, NBT, BSON, MessagePack, CBOR or protobuf, or a Minecraft region",
    args: z.object({
      path: z.string().describe("Local file holding the blob"),
    }),
    options: z.object({
      format: z
        .enum(["auto", ...BLOB_DECODERS, "mca"])
        .optional()
        .describe("auto (default) or a format to force"),
      layers: z
        .string()
        .optional()
        .describe(
          `Comma-separated layers to remove in order: ${BLOB_LAYERS.join(", ")}`,
        ),
      view: z.enum(BLOB_VIEWS).optional().describe("tree (default) or strings"),
      node: z
        .string()
        .optional()
        .describe("Path of a subtree to list, such as $.items[0]"),
      max_depth: z.coerce
        .number()
        .int()
        .optional()
        .describe("Levels below the node to include"),
      region_chunk: z.coerce
        .number()
        .int()
        .optional()
        .describe("Minecraft region chunk index (z*32+x) to decode"),
      range_offset: z.coerce
        .number()
        .int()
        .optional()
        .describe("Byte offset of the blob inside the file"),
      range_length: z.coerce
        .number()
        .int()
        .optional()
        .describe("Bytes to take from range_offset"),
      query: z
        .string()
        .optional()
        .describe("Case-insensitive path, key, type or value filter"),
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
    run: offlineInspectCommand(
      logger,
      CLI_COMMANDS.inspectDataBlob,
      async () => {
        // Load the decoder only when this command runs, keeping CLI startup light.
        const { createDataBlobService } =
          await import("../composition/blob.js");
        return createDataBlobService();
      },
      (args, options) => ({
        path: resolve(args.path),
        format: options.format,
        layers: layerList(options.layers),
        view: options.view,
        node: options.node,
        max_depth: options.max_depth,
        region_chunk: options.region_chunk,
        range_offset: options.range_offset,
        range_length: options.range_length,
        query: options.query,
        offset: options.offset,
        limit: options.limit,
      }),
    ),
  });
};
