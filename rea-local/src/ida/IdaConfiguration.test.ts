import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createIdaTarget } from "../../tests/fixtures/idaMcp.js";
import {
  readIdaConfiguration,
  readOfficialIdaConfiguration,
} from "./IdaConfiguration.js";
import { decodeIdaToolResult } from "./IdaMcpConnection.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

describe("IDA registration and MCP result boundaries", () => {
  it("reuses a direct or upstream mcpServers registration with no installation", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "mcp.json");
    for (const input of [
      { command: "python", args: ["server.py"] },
      {
        mcpServers: {
          "ida-pro-mcp": { command: "python", args: ["server.py"] },
          unrelated: { command: "untouched" },
        },
      },
    ]) {
      await writeFile(path, JSON.stringify(input));
      expect(readIdaConfiguration(path)).toMatchObject({
        ok: true,
        value: { command: "python", args: ["server.py"], mode: "attached" },
      });
    }
  });
  it("keeps the official Hex-Rays profile separate and headless-only", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "official-mcp.json");
    await writeFile(
      path,
      JSON.stringify({
        mcpServers: {
          "ida-hexrays": { command: "/opt/uvx", args: ["ida-mcp", "stdio"] },
          "ida-pro-mcp": { command: "/opt/third-party-idapro" },
        },
      }),
    );
    expect(readOfficialIdaConfiguration(path)).toMatchObject({
      ok: true,
      value: { command: "/opt/uvx", mode: "headless" },
    });
    await writeFile(
      path,
      JSON.stringify({ command: "/opt/uvx", mode: "attached" }),
    );
    const attached = readOfficialIdaConfiguration(path);
    expect(attached.ok).toBe(false);
    if (!attached.ok)
      expect(attached.error.settings[0]?.constraint).toContain("mode=headless");
  });

  it("validates local transport and lifecycle inputs without leaking auth into a profile", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "mcp.json");
    for (const input of [
      { url: "https://example.com/mcp" },
      { url: "http://token@127.0.0.1/mcp" },
      { command: "python", mode: "force_gui" },
      { command: "python", workspaceRoot: "relative" },
      { command: "python", args: "server.py" },
    ]) {
      await writeFile(path, JSON.stringify(input));
      expect(readIdaConfiguration(path).ok).toBe(false);
    }
    await writeFile(
      path,
      JSON.stringify({
        url: "http://127.0.0.1:8745/mcp",
        mode: "headless",
        headers: { Authorization: "Bearer fixture-secret" },
      }),
    );
    expect(readIdaConfiguration(path).ok).toBe(true);
    await writeFile(path, "malformed");
    expect(readIdaConfiguration(path).ok).toBe(false);
    expect(readIdaConfiguration(join(root, "absent")).ok).toBe(false);
  });
  it("parses FastMCP wrappers, structured dictionaries, text, arrays, and explicit errors", () => {
    expect(
      decodeIdaToolResult({
        content: [],
        structuredContent: { result: [{ address: "0x1" }] },
      }),
    ).toEqual([{ address: "0x1" }]);
    expect(
      decodeIdaToolResult({
        content: [],
        structuredContent: { address: "0x1", name: "f" },
      }),
    ).toEqual({ address: "0x1", name: "f" });
    expect(
      decodeIdaToolResult({ content: [{ type: "text", text: "int f() {}" }] }),
    ).toBe("int f() {}");
    expect(
      decodeIdaToolResult({ content: [{ type: "text", text: '{"data":[]}' }] }),
    ).toEqual({ data: [] });
    expect(() =>
      decodeIdaToolResult({
        content: [{ type: "text", text: "No function at 0x1" }],
        isError: true,
      }),
    ).toThrow("No function at 0x1");
    expect(() => decodeIdaToolResult({ content: "invalid" })).toThrow();
  });
});
