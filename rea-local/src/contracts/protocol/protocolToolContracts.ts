import {
  inferProtocolFieldsInputSchema,
  protocolFieldsSchema,
} from "../../domain/protocol/protocolFields.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free protocol field inference with CLI/MCP parity; captures are never replayed. */
export const PROTOCOL_TOOL_CONTRACTS = [
  {
    name: "infer_protocol_fields",
    ...toolContractMetadata("infer_protocol_fields"),
    kind: "artifact-provider",
    description:
      "Infer the message formats of an undocumented protocol (a game's netcode, a device's control channel) from a PCAP/PCAPNG capture or a file of hex messages, without sending anything, and return Evidence. UDP datagrams are taken as messages; TCP streams are reassembled and split by a detected length prefix, a line or NUL delimiter, or their segments. Messages are grouped into formats by a type field, direction or first word, and each format's fixed header is broken into fields: type, constants, length fields with their adjustment, counters, checksums (CRC-32/32C, Adler-32, CRC-16 variants, Fletcher, internet, sums, XOR) with the bytes they cover, epoch timestamps, floats, text, small enums, unique ids, and the variable part. Each field is a hypothesis with sample values.",
    inputSchema: inferProtocolFieldsInputSchema,
    outputSchema: evidenceResultOf(protocolFieldsSchema),
    examples: [
      {
        title: "Find the message formats of a game's UDP traffic",
        input: { path: "/captures/game.pcapng", transport: "udp", port: 7777 },
      },
      {
        title: "List the fields of one format",
        input: {
          path: "/captures/game.pcapng",
          port: 7777,
          view: "fields",
          format: 2,
        },
      },
      {
        title: "Analyse messages copied from a debugger as hex lines",
        input: { path: "/notes/packets.txt", view: "fields" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
