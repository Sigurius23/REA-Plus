import {
  externalMcpInputSchemas,
  externalMcpResultSchemas,
} from "../../domain/externalMcp/externalMcpAnalysis.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import type { ToolContract } from "../toolContractTypes.js";

/** Optional, explicitly configured bridge to caller-selected local MCP tools. */
export const EXTERNAL_MCP_TOOL_CONTRACTS = [
  {
    name: "list_external_mcp_servers",
    ...toolContractMetadata("list_external_mcp_servers"),
    description:
      "List only external MCP servers declared in the local REA_EXTERNAL_MCP_CONFIG file. Does not start a process or contact an endpoint; credential values and command arguments are never returned.",
    kind: "external-mcp-provider",
    inputSchema: externalMcpInputSchemas.list_external_mcp_servers,
    outputSchema: evidenceResultOf(
      externalMcpResultSchemas.list_external_mcp_servers,
    ),
    examples: [{ title: "List configured external MCP servers", input: {} }],
  },
  {
    name: "inspect_external_mcp_tools",
    ...toolContractMetadata("inspect_external_mcp_tools"),
    description:
      "Connect to one explicitly configured local stdio or loopback HTTP(S) MCP server and inspect its advertised tools, schemas, annotations, and REA+ allowlist status. Starts the configured stdio process or contacts the loopback endpoint. Upstream annotations are informational only; discovery does not establish target identity, tool safety, platform support, or compatibility.",
    kind: "external-mcp-provider",
    inputSchema: externalMcpInputSchemas.inspect_external_mcp_tools,
    outputSchema: evidenceResultOf(
      externalMcpResultSchemas.inspect_external_mcp_tools,
    ),
    examples: [
      {
        title: "Inspect a configured server's tools",
        input: { server_id: "radare2", offset: 0, limit: 25 },
      },
    ],
  },
  {
    name: "call_external_mcp_tool",
    ...toolContractMetadata("call_external_mcp_tool"),
    description:
      "Call one exact tool name explicitly listed in that server's allowedTools configuration after validating the supplied arguments against the upstream JSON Schema. This forwards an opaque external operation: it may mutate a target, change upstream session state, write files, launch processes, access networks, change UI state, or discard data. Review the upstream tool and its side effects before allowlisting. Evidence identifies the configured server and upstream result; caller arguments are stored only as a canonical SHA-256 digest and byte length. Text/JSON output is bounded, and image/audio/binary resource bytes are not copied into Evidence.",
    kind: "external-mcp-provider",
    inputSchema: externalMcpInputSchemas.call_external_mcp_tool,
    outputSchema: evidenceResultOf(
      externalMcpResultSchemas.call_external_mcp_tool,
    ),
    examples: [],
  },
] as const satisfies readonly ToolContract[];
