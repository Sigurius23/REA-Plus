import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from "@modelcontextprotocol/client/stdio";

import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import type { ExternalMcpRegistration } from "./ExternalMcpConfiguration.js";

export interface ExternalMcpTool {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema: unknown;
  readonly outputSchema?: unknown;
  readonly annotations?: unknown;
}

export interface ExternalMcpCallResult {
  readonly content?: readonly unknown[];
  readonly structuredContent?: unknown;
  readonly isError?: boolean;
}

export interface ExternalMcpConnection {
  connect(signal?: AbortSignal): Promise<readonly ExternalMcpTool[]>;
  discover(signal?: AbortSignal): Promise<readonly ExternalMcpTool[]>;
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<ExternalMcpCallResult>;
  serverInfo(): JsonValue;
  close(): Promise<void>;
}

export type ExternalMcpConnectionFactory = (
  registration: ExternalMcpRegistration,
  environment: Readonly<NodeJS.ProcessEnv>,
) => ExternalMcpConnection;

/** Create a caller-selected local MCP client; no server starts before connect. */
export const createExternalMcpConnection: ExternalMcpConnectionFactory = (
  registration,
  selectedEnvironment,
) => {
  const client = new Client({ name: "rea-external-tool-bridge", version: "1" });
  const environment = snapshotEnvironment(selectedEnvironment);
  const transport =
    registration.type === "stdio"
      ? new StdioClientTransport({
          command: registration.command,
          args: registration.args,
          env: {
            ...Object.fromEntries(
              DEFAULT_INHERITED_ENV_VARS.map((key) => [key, ""]),
            ),
            ...Object.fromEntries(
              DEFAULT_INHERITED_ENV_VARS.flatMap((key) => {
                const value = environment[key];
                return value === undefined || value.startsWith("()")
                  ? []
                  : [[key, value] as const];
              }),
            ),
            ...Object.fromEntries(
              Object.entries(snapshotEnvironment(registration.env)).filter(
                (entry): entry is [string, string] => entry[1] !== undefined,
              ),
            ),
          },
          stderr: "pipe",
        })
      : new StreamableHTTPClientTransport(new URL(registration.url), {
          requestInit: { headers: registration.headers, redirect: "error" },
        });

  // Never retain child diagnostics in REA+ logs or Evidence.
  if (transport instanceof StdioClientTransport)
    transport.stderr?.on("data", () => undefined);

  let tools: readonly ExternalMcpTool[] | undefined;
  let discoveryReturned = false;
  let acquisition: Promise<readonly ExternalMcpTool[]> | undefined;
  let closing: Promise<void> | undefined;
  let closed = false;

  const connect = async (
    signal?: AbortSignal,
  ): Promise<readonly ExternalMcpTool[]> => {
    if (closed) throw new Error("External MCP connection is closed");
    if (signal?.aborted === true)
      throw new Error("External MCP request cancelled");
    if (tools !== undefined) return tools;
    if (acquisition !== undefined) return waitForCaller(acquisition, signal);
    const pending = (async () => {
      try {
        await client.connect(transport, {
          timeout: registration.timeoutMs,
          ...(signal === undefined ? {} : { signal }),
        });
        const result = await client.listTools(
          {},
          {
            timeout: registration.timeoutMs,
            ...(signal === undefined ? {} : { signal }),
          },
        );
        tools = result.tools as unknown as readonly ExternalMcpTool[];
        return tools;
      } catch (cause: unknown) {
        await closeAfterFailure();
        throw redactTransportFailure(cause, registration);
      }
    })();
    acquisition = pending;
    try {
      return await waitForCaller(pending, signal);
    } finally {
      if (acquisition === pending) acquisition = undefined;
    }
  };

  const closeAfterFailure = async (): Promise<void> => {
    if (closing !== undefined) return closing;
    closing = client.close().catch((cause: unknown) => {
      throw redactTransportFailure(cause, registration);
    });
    try {
      await closing;
      closed = true;
    } finally {
      closing = undefined;
    }
  };

  return {
    connect,
    async discover(signal) {
      const current = await connect(signal);
      if (!discoveryReturned) {
        discoveryReturned = true;
        return current;
      }
      try {
        const result = await client.listTools(
          {},
          {
            timeout: registration.timeoutMs,
            ...(signal === undefined ? {} : { signal }),
          },
        );
        tools = result.tools as unknown as readonly ExternalMcpTool[];
        return tools;
      } catch (cause: unknown) {
        throw redactTransportFailure(cause, registration);
      }
    },
    async call(name, args, signal) {
      await connect(signal);
      if (signal?.aborted === true)
        throw new Error("External MCP request cancelled");
      try {
        const result = await client.callTool(
          { name, arguments: { ...args } },
          {
            timeout: registration.timeoutMs,
            ...(signal === undefined ? {} : { signal }),
          },
        );
        return result as unknown as ExternalMcpCallResult;
      } catch (cause: unknown) {
        throw redactTransportFailure(cause, registration);
      }
    },
    serverInfo: () => jsonValueSchema.parse(client.getServerVersion() ?? null),
    async close() {
      if (closed) return;
      if (closing !== undefined) return closing;
      closing = client.close().catch((cause: unknown) => {
        throw redactTransportFailure(cause, registration);
      });
      try {
        await closing;
        closed = true;
        tools = undefined;
      } finally {
        closing = undefined;
      }
    },
  };
};

const waitForCaller = <Value>(
  promise: Promise<Value>,
  signal?: AbortSignal,
): Promise<Value> => {
  if (signal?.aborted === true)
    return Promise.reject(new Error("External MCP request cancelled"));
  if (signal === undefined) return promise;
  return new Promise((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(new Error("External MCP request cancelled"));
    };
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (cause: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(cause);
      },
    );
  });
};

/** Remove configured HTTP credentials from SDK-authored failure messages. */
const redactTransportFailure = (
  cause: unknown,
  registration: ExternalMcpRegistration,
): Error => {
  let message =
    cause instanceof Error ? cause.message : "Unknown external MCP failure";
  if (registration.type === "http") {
    for (const value of Object.values(registration.headers)) {
      const credential = value.match(/^(?:Bearer|Basic)\s+([\s\S]+)$/iu)?.[1];
      for (const secret of [value, credential])
        if (secret !== undefined && secret.length > 0)
          message = message
            .split(secret)
            .join("[redacted transport credential]");
    }
  }
  return new Error(message, { cause });
};
