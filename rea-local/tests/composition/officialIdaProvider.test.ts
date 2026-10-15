import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { parseConfig } from "../../src/config/parseConfig.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";
import { IDA_OFFICIAL_PROVIDER_IDENTITY } from "../../src/ida/IdaProviderCapabilities.js";
import type { IdaMcpConnection } from "../../src/ida/IdaMcpConnection.js";
import { OfficialIdaProvider } from "../../src/ida/OfficialIdaProvider.js";
import { createIdaTarget } from "../fixtures/idaMcp.js";
import { createTestBinarySession } from "../fixtures/binarySession.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

class RecordingOfficialIda implements IdaMcpConnection {
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  inputPath = "";
  closed = false;

  constructor(private readonly sha256: string) {}

  async connect() {
    return [
      "open_database",
      "execute_python",
      "reference",
      "list_databases",
      "save_database",
      "close_database",
    ];
  }

  async call(name: string, args: Readonly<Record<string, JsonValue>>) {
    this.calls.push({ name, args });
    if (name === "open_database") {
      this.inputPath = String(args.path);
      return {
        instance_id: "private-worker",
        backend: "idalib",
        status: "attached",
      };
    }
    if (name === "list_databases")
      return {
        instances: this.closed
          ? []
          : [
              {
                path: this.inputPath,
                backend: "idalib",
                status: "attached",
                instance_id: "private-worker",
                error: null,
              },
            ],
      };
    if (name === "close_database") {
      this.closed = true;
      return { closed: true };
    }
    if (name === "execute_python") {
      const code = String(args.code);
      const result = code.includes("retrieve_input_file_sha256")
        ? {
            path: this.inputPath,
            module: "input.bin",
            sha256: this.sha256,
            base: "0x1000",
          }
        : code.includes("idc.get_name_ea_simple")
          ? { address: "0x1000", name: "main", size: "0x20" }
          : code.includes("idc.decompile")
            ? "int main(void) { return 42; }"
            : null;
      return { result: JSON.stringify(result), stdout: "", stderr: "" };
    }
    throw new Error(`Unexpected official IDA MCP tool: ${name}`);
  }

  serverInfo(): JsonValue {
    return { name: "ida", version: "fixture" };
  }

  async close() {
    this.calls.push({ name: "mcp_close", args: {} });
  }
}

describe("official Hex-Rays IDA analysis provider", () => {
  it("binds normalized results to the private input copy and releases only its headless lease", async () => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const registration = join(root, "official-mcp.json");
    await writeFile(
      registration,
      JSON.stringify({
        mcpServers: {
          "ida-hexrays": {
            command: "/opt/uvx",
            args: ["ida-mcp", "stdio"],
            workspaceRoot: root,
          },
        },
      }),
    );
    const config = parseConfig({
      REA_ANALYSIS_PROVIDER: "ida-official",
      REA_IDA_OFFICIAL_MCP_CONFIG: registration,
    });
    if (!config.ok) throw config.error;
    const upstream = new RecordingOfficialIda(target.sha256);
    const provider = new OfficialIdaProvider(config.value, {}, () => upstream);
    expect(provider.identity().id).toBe("ida-official");
    expect(provider.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: {
        mode: "headless-private-copy",
        user_database_mutation: false,
      },
    });
    const resolution = await provider.resolveAnalysisProfile(target);
    if (!resolution.ok) throw resolution.error;
    expect(resolution.value.profile.provider).toEqual(
      IDA_OFFICIAL_PROVIDER_IDENTITY,
    );

    const session = createTestBinarySession(provider);
    expect((await session.open(target.path)).ok).toBe(true);
    expect(upstream.calls).toEqual([]);
    const result = await session.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    if (!result.ok) throw result.error;
    expect(result.value.result).toBe("int main(void) { return 42; }");
    expect(result.ok && result.value.provider.id).toBe("ida-official");
    expect(upstream.inputPath).not.toBe(target.path);
    expect(upstream.calls.some(({ name }) => name === "save_database")).toBe(
      false,
    );
    expect(upstream.calls.some(({ name }) => name === "close_database")).toBe(
      false,
    );

    expect((await session.close()).ok).toBe(true);
    expect(
      upstream.calls.filter(({ name }) => name === "close_database"),
    ).toHaveLength(1);
    expect(
      upstream.calls.find(({ name }) => name === "close_database")?.args,
    ).toEqual({ instance_id: "private-worker" });
    expect(upstream.calls.at(-1)?.name).toBe("mcp_close");
  });
});
