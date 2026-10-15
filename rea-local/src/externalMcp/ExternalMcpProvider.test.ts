import { describe, expect, it, vi } from "vitest";

import type { ExternalMcpAnalysisPort } from "../application/externalMcp/ExternalMcpAnalysisPort.js";
import type { ExternalMcpRequest } from "../domain/externalMcp/externalMcpAnalysis.js";
import { ExternalMcpAnalysisService } from "./ExternalMcpAnalysisService.js";
import type { ExternalMcpConfiguration } from "./ExternalMcpConfiguration.js";
import type {
  ExternalMcpCallResult,
  ExternalMcpConnection,
  ExternalMcpConnectionFactory,
  ExternalMcpTool,
} from "./ExternalMcpConnection.js";
import { ExternalMcpProvider } from "./ExternalMcpProvider.js";

const serverConfiguration: ExternalMcpConfiguration = {
  mcpServers: {
    ghidra: {
      type: "stdio",
      name: "Ghidra MCP test server",
      command: "/test/ghidra-mcp",
      args: [],
      env: {},
      timeoutMs: 1000,
      allowedTools: ["list_functions", "decompile_function"],
    },
  },
};

const advertisedTool = {
  name: "decompile_function",
  title: "Decompile function",
  description: "Return pseudocode for one analyzed function.",
  inputSchema: {
    type: "object",
    properties: { address: { type: "string" } },
    required: ["address"],
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: { pseudocode: { type: "string" } },
  },
  annotations: {
    readOnlyHint: true,
    idempotentHint: true,
    destructiveHint: false,
    openWorldHint: false,
  },
} as ExternalMcpTool;

const connection = (
  callResult: ExternalMcpCallResult = {
    content: [{ type: "text", text: "int answer(void) { return 42; }" }],
    structuredContent: { pseudocode: "int answer(void) { return 42; }" },
  },
) => {
  const call = vi.fn(async () => callResult);
  const close = vi.fn(async () => undefined);
  const liveConnection: ExternalMcpConnection = {
    connect: vi.fn(async () => [advertisedTool]),
    discover: vi.fn(async () => [advertisedTool]),
    call,
    serverInfo: () => ({ name: "ghidra-mcp", version: "0.9.1" }),
    close,
  };
  return { liveConnection, call, close };
};

const bridge = (liveConnection: ExternalMcpConnection) =>
  new ExternalMcpProvider(serverConfiguration, {}, () => liveConnection);

const request = (
  operation: ExternalMcpRequest["operation"],
  input: ExternalMcpRequest["input"],
): ExternalMcpRequest => ({ operation, input }) as ExternalMcpRequest;

describe("External MCP registration and discovery", () => {
  it("lists only local registrations and does not start their processes", async () => {
    const factory = vi.fn<ExternalMcpConnectionFactory>();
    const provider = new ExternalMcpProvider(serverConfiguration, {}, factory);
    const result = await provider.execute(
      request("list_external_mcp_servers", {}),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(result.value.result).toMatchObject({
      configured: true,
      servers: [
        {
          server_id: "ghidra",
          name: "Ghidra MCP test server",
          transport: "stdio",
          allowed_tools: ["list_functions", "decompile_function"],
        },
      ],
    });
    expect(factory).not.toHaveBeenCalled();
  });

  it("discovers tools with exact allowlist status and source version", async () => {
    const { liveConnection } = connection();
    const provider = bridge(liveConnection);
    const result = await provider.execute(
      request("inspect_external_mcp_tools", {
        server_id: "ghidra",
        offset: 0,
        limit: 25,
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(result.value.provider).toEqual({
      id: "external-mcp:ghidra",
      name: "External MCP: Ghidra MCP test server",
      version: "0.9.1",
    });
    expect(result.value.result).toMatchObject({
      server_id: "ghidra",
      server_version: { name: "ghidra-mcp", version: "0.9.1" },
      total_tools: 1,
      tools: [
        {
          name: "decompile_function",
          allowed: true,
          description_truncated: false,
        },
      ],
    });
  });
});

describe("External MCP call forwarding", () => {
  it("calls an allowlisted tool and retains the upstream result as Evidence", async () => {
    const { liveConnection, call } = connection({
      content: [{ type: "text", text: "decompiled pseudocode" }],
      structuredContent: { pseudocode: "decompiled pseudocode" },
      isError: true,
    });
    const provider = bridge(liveConnection);
    const service = new ExternalMcpAnalysisService(provider);
    const result = await service.execute("call_external_mcp_tool", {
      server_id: "ghidra",
      tool_name: "decompile_function",
      arguments: { address: "0x401000" },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(call).toHaveBeenCalledWith(
      "decompile_function",
      { address: "0x401000" },
      undefined,
    );
    expect(result.value.provider).toMatchObject({
      id: "external-mcp:ghidra",
      version: "0.9.1",
    });
    expect(result.value.authority).toBe("external-service");
    expect(result.value.normalized_result).toMatchObject({
      server_id: "ghidra",
      tool_name: "decompile_function",
      upstream_is_error: true,
      structured_content: { pseudocode: "decompiled pseudocode" },
      content: [{ type: "text", text: "decompiled pseudocode" }],
    });
    expect(result.value.parameters).toMatchObject({
      server_id: "ghidra",
      tool_name: "decompile_function",
      arguments_bytes: expect.any(Number),
      arguments_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
    });
    expect(JSON.stringify(result.value.parameters)).not.toContain("0x401000");
    expect(result.value.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("not independently audited"),
      ]),
    );
  });

  it("refuses a non-allowlisted tool before connecting", async () => {
    const { liveConnection, call } = connection();
    const provider = bridge(liveConnection);
    const result = await provider.execute(
      request("call_external_mcp_tool", {
        server_id: "ghidra",
        tool_name: "run_script",
        arguments: {},
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected the call to be refused");
    expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(liveConnection.connect).not.toHaveBeenCalled();
    expect(call).not.toHaveBeenCalled();
  });

  it("validates arguments against the upstream JSON Schema", async () => {
    const { liveConnection, call } = connection();
    const provider = bridge(liveConnection);
    const result = await provider.execute(
      request("call_external_mcp_tool", {
        server_id: "ghidra",
        tool_name: "decompile_function",
        arguments: { address: 123 },
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected schema validation to fail");
    expect(result.error._tag).toBe("AnalysisInputError");
    expect(call).not.toHaveBeenCalled();
  });
});

describe("External MCP output projection", () => {
  it("bounds structured output and represents binary blocks as metadata", async () => {
    const { liveConnection } = connection({
      content: [{ type: "image", data: "aGVsbG8=", mimeType: "image/png" }],
      structuredContent: { data: "x".repeat(70_000) },
    });
    const provider = bridge(liveConnection);
    const result = await provider.execute(
      request("call_external_mcp_tool", {
        server_id: "ghidra",
        tool_name: "decompile_function",
        arguments: { address: "0x401000" },
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(result.value.result).toMatchObject({
      structured_content: null,
      structured_content_omitted: true,
      content: [
        {
          type: "image",
          mime_type: "image/png",
          byte_length: 5,
          omitted: true,
        },
      ],
    });
  });
});

describe("External MCP connection lifecycle", () => {
  it("closes its connection and rejects subsequent execution", async () => {
    const { liveConnection, close } = connection();
    const provider = bridge(liveConnection);
    await provider.execute(
      request("inspect_external_mcp_tools", {
        server_id: "ghidra",
        offset: 0,
        limit: 25,
      }),
    );
    await provider.close();
    expect(close).toHaveBeenCalledOnce();
    const result = await provider.execute(
      request("list_external_mcp_servers", {}),
    );
    expect(result.ok).toBe(false);
  });

  it("implements the external MCP analysis port", () => {
    const provider: ExternalMcpAnalysisPort = bridge(
      connection().liveConnection,
    );
    expect(provider).toHaveProperty("execute");
    expect(provider).toHaveProperty("close");
  });
});
