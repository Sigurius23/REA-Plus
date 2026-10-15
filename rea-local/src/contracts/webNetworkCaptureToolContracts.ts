import {
  inspectWebNetworkCaptureInputSchema,
  webNetworkCaptureSchema,
} from "../domain/webNetworkCapture.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Historical inspection is distinct from live browser capture and runtime authority. */
export const WEB_NETWORK_CAPTURE_TOOL_CONTRACTS = [
  {
    name: "inspect_web_network_capture",
    ...toolContractMetadata("inspect_web_network_capture"),
    description:
      "Inspect retained local HAR 1.2, native mitmproxy, classic PCAP or PCAPNG records without contacting recorded URLs. Returns original ordinals, JSON pointers or byte ranges, preserved producer fields, precise numeric representations and exact exposed frame/body bytes inline. Excludes known transport credentials and explicitly marked values. Validates every record before ordinal selection; HAR and packet-capture decoders retain only requested records, while native mitmproxy decoding completes before shared selection. Malformed or oversized captures return no partial success. Duplicate HAR members are invalid; prototype-named members such as __proto__ are preserved as ordinary own JSON members without prototype mutation. Packet decoding preserves frame provenance and derives supported link/IP/TCP/UDP metadata, normalized transport five-tuples and application metadata that begins in one packet: HTTP/1.x heads, TLS ClientHello/ServerHello fields and DNS messages. HTTP credential values are removed and frames carrying them withheld. It does not decrypt TLS, reassemble streams or establish runtime attribution. Uses owned temporary files and bounded offline processes. Native mitmproxy requires caller-supplied mitmdump 12.2.3 on Linux. Browser transaction IDs, runtime attribution and original bytes of HAR Unicode text remain unknown.",
    kind: "browser-provider",
    inputSchema: inspectWebNetworkCaptureInputSchema,
    outputSchema: evidenceResultOf(webNetworkCaptureSchema),
    examples: [
      {
        title: "Inspect historical HAR entries",
        input: {
          capture_path: "/captures/session.har",
          format: "har",
          record_ordinals: [0, 2],
        },
      },
      {
        title: "Inspect selected packet frames",
        input: {
          capture_path: "/captures/session.pcapng",
          format: "pcapng",
          record_ordinals: [0, 12],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
