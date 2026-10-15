import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { parseConfig } from "../config/parseConfig.js";
import {
  EXTERNAL_MCP_CONFIG_MAX_BYTES,
  readExternalMcpConfiguration,
} from "./ExternalMcpConfiguration.js";

let root = "";
beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-external-mcp-config-"));
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const writeConfig = async (source: string): Promise<string> => {
  const path = join(root, `config-${Math.random().toString(16).slice(2)}.json`);
  await writeFile(path, source, "utf8");
  return path;
};

describe("external MCP registration configuration", () => {
  it("defaults to no external servers without starting or contacting anything", () => {
    expect(readExternalMcpConfiguration(undefined)).toEqual({
      ok: true,
      value: { mcpServers: {} },
    });
  });

  it("accepts an explicit stdio command and exact tool allowlist", async () => {
    const path = await writeConfig(
      JSON.stringify({
        mcpServers: {
          ghidra: {
            type: "stdio",
            name: "Ghidra MCP",
            command: "/opt/ghidra-mcp/server",
            args: ["--stdio"],
            env: { GHIDRA_HOME: "/opt/ghidra" },
            timeoutMs: 90000,
            allowedTools: ["list_functions", "decompile_function"],
          },
        },
      }),
    );
    const parsed = readExternalMcpConfiguration(path);
    expect(parsed).toEqual({
      ok: true,
      value: {
        mcpServers: {
          ghidra: {
            type: "stdio",
            name: "Ghidra MCP",
            command: "/opt/ghidra-mcp/server",
            args: ["--stdio"],
            env: { GHIDRA_HOME: "/opt/ghidra" },
            timeoutMs: 90000,
            allowedTools: ["list_functions", "decompile_function"],
          },
        },
      },
    });
  });

  it.each([
    ["https://analysis.example/mcp", "non-loopback host"],
    ["http://127.0.0.1:8765/mcp?token=secret", "query string"],
    ["http://user:secret@localhost:8765/mcp", "URL credentials"],
    ["http://localhost:8765/mcp#fragment", "URL fragment"],
  ])("rejects an HTTP endpoint containing a %s", async (url) => {
    const path = await writeConfig(
      JSON.stringify({
        mcpServers: {
          remote: {
            type: "http",
            url,
            allowedTools: ["inspect"],
          },
        },
      }),
    );
    const parsed = readExternalMcpConfiguration(path);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("Expected invalid configuration");
    expect(projectAnalysisError(parsed.error).code).toBe(
      "configuration_invalid",
    );
    expect(JSON.stringify(projectAnalysisError(parsed.error))).not.toContain(
      "secret",
    );
  });

  it("rejects duplicate allowlist entries, unknown settings, and oversized files", async () => {
    const duplicatePath = await writeConfig(
      JSON.stringify({
        mcpServers: {
          local: {
            type: "stdio",
            command: "server",
            allowedTools: ["inspect", "inspect"],
          },
        },
      }),
    );
    expect(readExternalMcpConfiguration(duplicatePath).ok).toBe(false);

    const unknownPath = await writeConfig(
      JSON.stringify({ mcpServers: {}, allowAll: true }),
    );
    expect(readExternalMcpConfiguration(unknownPath).ok).toBe(false);

    const oversizedPath = await writeConfig(
      `{"mcpServers":{}}${" ".repeat(EXTERNAL_MCP_CONFIG_MAX_BYTES)}`,
    );
    expect(readExternalMcpConfiguration(oversizedPath).ok).toBe(false);
  });

  it("validates the environment path as absolute without echoing its value", () => {
    const parsed = parseConfig({ REA_EXTERNAL_MCP_CONFIG: "relative.json" });
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("Expected invalid configuration");
    const projection = projectAnalysisError(parsed.error);
    expect(projection).toMatchObject({
      details: {
        settings: [
          expect.objectContaining({ setting: "REA_EXTERNAL_MCP_CONFIG" }),
        ],
      },
    });
    expect(JSON.stringify(projection)).not.toContain("relative.json");
  });
});
