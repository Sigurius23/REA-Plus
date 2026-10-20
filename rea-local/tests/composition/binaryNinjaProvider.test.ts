import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { parseConfig } from "../../src/config/parseConfig.js";
import { BinaryNinjaProvider } from "../../src/binaryNinja/BinaryNinjaProvider.js";
import {
  BINARY_NINJA_FIXTURE_TOOLS,
  RecordingBinaryNinja,
} from "../fixtures/binaryNinjaMcp.js";
import { createIdaTarget } from "../fixtures/idaMcp.js";
import { createTestBinarySession } from "../fixtures/binarySession.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

describe("official Binary Ninja provider composition", () => {
  it("resolves its caller-supplied registration and returns normalized Evidence without save or close tools", async () => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const registrationPath = join(root, "external-mcp.json");
    await writeFile(
      registrationPath,
      JSON.stringify({
        mcpServers: {
          "binary-ninja": {
            type: "stdio",
            command: "/opt/binaryninja_mcp",
            allowedTools: BINARY_NINJA_FIXTURE_TOOLS.map(({ name }) => name),
          },
        },
      }),
    );
    const config = parseConfig({
      REA_ANALYSIS_PROVIDER: "binary-ninja",
      REA_EXTERNAL_MCP_CONFIG: registrationPath,
    });
    if (!config.ok) throw config.error;

    const upstream = new RecordingBinaryNinja(target.path, target.sha256);
    const provider = new BinaryNinjaProvider(config.value, {}, () => upstream);
    expect(provider.identity().id).toBe("binary-ninja");
    expect(
      provider.inspectTargetSupport({
        path: target.path,
        sha256: target.sha256,
        kind: "executable",
        format: "dex",
        architecture: "dalvik",
        availableArchitectures: ["dalvik"],
        dex: { version: "039" },
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
    expect(provider.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: {
        server_id: "binary-ninja",
        live_connection_probed: false,
      },
    });
    const resolved = await provider.resolveAnalysisProfile(target);
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile.provider.id).toBe("binary-ninja");

    const session = createTestBinarySession(provider);
    expect((await session.open(target.path)).ok).toBe(true);
    expect(upstream.calls).toEqual([]);
    const result = await session.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    if (!result.ok) throw result.error;
    expect(result.value.result).toBe("int main(void) { return 42; }");
    expect(result.value.provider.id).toBe("binary-ninja");
    expect(result.value.analysisProfile?.digest).toBe(
      resolved.value.profile.digest,
    );

    expect((await session.close()).ok).toBe(true);
    const invoked = upstream.calls.map(({ name }) => name);
    expect(invoked).toContain("bn_open_item_open");
    expect(invoked).toContain("bn_function_decompile");
    expect(invoked).not.toContain("bn_open_item_save");
    expect(invoked).not.toContain("bn_open_item_close");
    expect(upstream.closed).toBe(true);
  });
});
