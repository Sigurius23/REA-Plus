import {
  dataBlobSchema,
  inspectDataBlobInputSchema,
} from "../../domain/blob/dataBlob.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free blob decoder with CLI/MCP parity; payloads are decoded, never run. */
export const DATA_BLOB_TOOL_CONTRACTS = [
  {
    name: "inspect_data_blob",
    ...toolContractMetadata("inspect_data_blob"),
    kind: "artifact-provider",
    description:
      "Decode a save game, cache, settings blob or captured packet payload without a schema and return Evidence of its structure. Base64, hex, gzip, zlib, zstd and LZ4 frame layers are removed automatically (raw deflate and Brotli when named), then the payload is decoded as JSON, Minecraft NBT (Java or Bedrock), BSON, MessagePack, CBOR or Protocol Buffers (schema-less, as protoc --decode_raw reads it), keeping every format that decodes the whole payload and ranking them by plausibility. The tree view lists every node with a path (such as $.items[1].name or $.9[0].1), type, value, other readings (a varint as int64 or zigzag, fixed32 as float, packed varints) and byte range; the strings view lists text leaves. Minecraft region files (.mca) list their chunks, and region_chunk decodes one. range_offset and range_length select a blob inside a larger file, and node and max_depth narrow the listing to a subtree.",
    inputSchema: inspectDataBlobInputSchema,
    outputSchema: evidenceResultOf(dataBlobSchema),
    examples: [
      {
        title: "Decode a save file of unknown format",
        input: { path: "/games/game/saves/slot1.sav" },
      },
      {
        title: "Read one player's data in a Minecraft region",
        input: {
          path: "/minecraft/world/region/r.0.0.mca",
          region_chunk: 33,
          node: "$.Level",
          max_depth: 2,
        },
      },
      {
        title: "Decode a protobuf payload cut out of a packet",
        input: {
          path: "/captures/packet-0042.bin",
          range_offset: 8,
          format: "protobuf",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
