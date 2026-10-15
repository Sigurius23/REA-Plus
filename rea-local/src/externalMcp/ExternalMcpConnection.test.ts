import { describe, expect, it } from "vitest";

import type { ExternalMcpRegistration } from "./ExternalMcpConfiguration.js";
import { createExternalMcpConnection } from "./ExternalMcpConnection.js";

const serverSource = `
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";

const server = new McpServer({ name: "rea-external-mcp-fixture", version: "1.0.0" });
server.registerTool(
  "echo",
  {
    title: "Echo",
    description: "Echo a caller-provided string.",
    inputSchema: { value: z.string() },
    outputSchema: { result: z.string() },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ value }) => ({
    content: [{ type: "text", text: value }],
    structuredContent: { result: value },
  }),
);
await server.connect(new StdioServerTransport());
`;

describe("External MCP SDK connection", () => {
  it("retains the advertised output schema and forwards calls over stdio", async () => {
    const registration: ExternalMcpRegistration = {
      type: "stdio",
      command: process.execPath,
      args: ["--input-type=module", "-e", serverSource],
      env: {},
      timeoutMs: 10_000,
      allowedTools: ["echo"],
    };
    const connection = createExternalMcpConnection(registration, process.env);

    try {
      const tools = await connection.connect();
      expect(tools).toHaveLength(1);
      expect(tools[0]).toMatchObject({
        name: "echo",
        title: "Echo",
        inputSchema: expect.objectContaining({
          properties: { value: { type: "string" } },
        }),
        outputSchema: expect.objectContaining({
          properties: { result: { type: "string" } },
        }),
        annotations: { readOnlyHint: true, destructiveHint: false },
      });
      expect(connection.serverInfo()).toMatchObject({
        name: "rea-external-mcp-fixture",
        version: "1.0.0",
      });
      expect(await connection.call("echo", { value: "hello" })).toMatchObject({
        structuredContent: { result: "hello" },
        content: [{ type: "text", text: "hello" }],
      });
    } finally {
      await connection.close();
    }
  });
});
