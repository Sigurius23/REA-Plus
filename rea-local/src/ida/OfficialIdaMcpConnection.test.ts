import { describe, expect, it } from "vitest";

import type { IdaConfiguration } from "./IdaConfiguration.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { OfficialIdaMcpConnection } from "./OfficialIdaMcpConnection.js";
import type { JsonValue } from "../domain/jsonValue.js";

const OFFICIAL_TOOLS = [
  "open_database",
  "execute_python",
  "reference",
  "list_databases",
  "save_database",
  "close_database",
] as const;

class RecordingOfficialIda implements IdaMcpConnection {
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  closed = false;
  path = "/tmp/rea-private/input.bin";

  async connect() {
    return OFFICIAL_TOOLS;
  }

  async call(name: string, args: Readonly<Record<string, JsonValue>>) {
    this.calls.push({ name, args });
    if (name === "open_database")
      return { instance_id: "worker-1", backend: "idalib", status: "current" };
    if (name === "list_databases")
      return {
        instances: [
          {
            path: this.path,
            backend: "idalib",
            status: "attached",
            instance_id: "worker-1",
            error: null,
          },
        ],
      };
    if (name === "close_database") return { closed: true };
    if (name === "execute_python") {
      const code = String(args.code);
      const result = code.includes("retrieve_input_file_sha256")
        ? {
            path: this.path,
            module: "input.bin",
            sha256: "a".repeat(64),
            base: "0x1000",
          }
        : {
            data: [{ address: "0x1000", name: "main", size: "0x20" }],
            next_offset: null,
          };
      return { result: JSON.stringify(result), stdout: "", stderr: "" };
    }
    throw new Error(`Unexpected upstream tool: ${name}`);
  }

  serverInfo(): JsonValue {
    return { name: "ida", version: "fixture" };
  }

  async close() {
    this.closed = true;
  }
}

const configuration: IdaConfiguration = {
  type: "stdio",
  command: "/opt/uvx",
  args: ["ida-mcp", "stdio"],
  env: {},
  mode: "headless",
  timeoutMs: 10_000,
};

describe("official Hex-Rays IDA MCP normalization", () => {
  it("accepts only the official tool contract and reports detected tools on mismatch", async () => {
    const incomplete: IdaMcpConnection = {
      connect: async () => ["open_database", "execute_python"],
      call: async () => null,
      serverInfo: () => null,
      close: async () => undefined,
    };
    const connection = new OfficialIdaMcpConnection(incomplete, configuration);
    await expect(connection.connect()).rejects.toThrow(
      /Missing tools: reference, list_databases, save_database, close_database.*Detected tools: open_database, execute_python/u,
    );
  });

  it("binds execution to a private idalib lease and normalizes metadata and inventories", async () => {
    const upstream = new RecordingOfficialIda();
    const connection = new OfficialIdaMcpConnection(upstream, configuration);
    expect(await connection.connect()).toContain("list_functions");

    const opened = await connection.call("idb_open", {
      input_path: upstream.path,
      mode: "force_headless",
      run_auto_analysis: true,
      build_caches: true,
      init_hexrays: true,
    });
    expect(opened).toMatchObject({
      success: true,
      session: {
        session_id: "worker-1",
        input_path: upstream.path,
        backend: "worker",
      },
    });
    expect(
      upstream.calls.find(({ name }) => name === "open_database")?.args,
    ).toEqual({ path: upstream.path, set_current: false });

    expect(await connection.call("idb_list", {})).toMatchObject({
      sessions: [
        {
          session_id: "worker-1",
          input_path: upstream.path,
          owned: true,
          backend: "worker",
          is_active: false,
        },
      ],
    });
    expect(await connection.call("get_metadata", {})).toMatchObject({
      path: upstream.path,
      sha256: "a".repeat(64),
      base: "0x1000",
    });
    expect(
      await connection.call("list_functions", { offset: 0, count: 100 }),
    ).toMatchObject({
      data: [{ address: "0x1000", name: "main", size: "0x20" }],
      next_offset: null,
    });
    const scriptCall = upstream.calls.find(
      ({ name, args }) =>
        name === "execute_python" &&
        String(args.code).includes("idautils.Functions()"),
    );
    expect(scriptCall?.args).toMatchObject({ instance_id: "worker-1" });
    expect(String(scriptCall?.args.code)).toContain("json.loads(");

    await expect(
      connection.call("idb_close", { database: "other-database" }),
    ).rejects.toThrow(/Refusing to close/u);
    expect(upstream.calls.some(({ name }) => name === "close_database")).toBe(
      false,
    );
    expect(
      await connection.call("idb_close", { database: "worker-1" }),
    ).toMatchObject({ success: true, saved: false, backend: "worker" });
    expect(
      upstream.calls.filter(({ name }) => name === "close_database"),
    ).toHaveLength(1);
    await connection.close();
    expect(upstream.closed).toBe(true);
  });

  it("never interpolates a caller-supplied symbol into executable Python source", async () => {
    const upstream = new RecordingOfficialIda();
    const connection = new OfficialIdaMcpConnection(upstream, configuration);
    await connection.connect();
    await connection.call("idb_open", { input_path: upstream.path });
    await connection.call("get_function_by_name", {
      name: "x'); __import__('os').remove('/tmp/sentinel'); ('",
    });
    const execution = upstream.calls.find(
      ({ name }) => name === "execute_python",
    );
    expect(execution).toBeDefined();
    const injection = "x'); __import__('os').remove('/tmp/sentinel'); ('";
    expect(String(execution?.args.code)).toContain(
      `args = json.loads(${JSON.stringify(JSON.stringify({ name: injection }))})`,
    );
  });
});
