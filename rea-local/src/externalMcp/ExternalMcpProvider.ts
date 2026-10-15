import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { PRODUCT_IDENTITY } from "../identity.js";
import type {
  ExternalMcpAnalysisPort,
  ExternalMcpExecutionOptions,
  ExternalMcpObservation,
  ExternalMcpProviderIdentity,
} from "../application/externalMcp/ExternalMcpAnalysisPort.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type {
  ExternalMcpConfiguration,
  ExternalMcpRegistration,
} from "./ExternalMcpConfiguration.js";
import {
  createExternalMcpConnection,
  type ExternalMcpCallResult,
  type ExternalMcpConnection,
  type ExternalMcpConnectionFactory,
  type ExternalMcpTool,
} from "./ExternalMcpConnection.js";
import type {
  ExternalMcpOperation,
  ExternalMcpRequest,
} from "../domain/externalMcp/externalMcpAnalysis.js";

const MAX_INPUT_ARGUMENT_BYTES = 65_536;
const MAX_SCHEMA_BYTES = 32_768;
const MAX_TOOL_DESCRIPTION_BYTES = 8_192;
const MAX_CONTENT_ITEMS = 64;
const MAX_CONTENT_TEXT_BYTES = 16_384;
const MAX_CONTENT_TOTAL_TEXT_BYTES = 131_072;
const MAX_STRUCTURED_CONTENT_BYTES = 65_536;
const MAX_METADATA_TEXT_BYTES = 4_096;

const CONNECTED_SERVER_LIMITATION =
  "External MCP tools are user-supplied and were not independently audited; upstream annotations and descriptions are informational, not a safety guarantee.";
const ACTIVE_TARGET_LIMITATION =
  "REA+ cannot independently bind an upstream MCP server's internal target or analysis database to the active REA+ artifact.";
const RESPONSE_LIMITATION =
  "Upstream output is retained only as a bounded JSON/text projection; image, audio, and binary resource bytes are represented by metadata, not copied into Evidence.";

/** User-selected analysis tools accessed through an explicitly configured MCP server. */
export class ExternalMcpProvider implements ExternalMcpAnalysisPort {
  private readonly servers: Readonly<Record<string, ExternalMcpRegistration>>;
  private readonly environment: Readonly<NodeJS.ProcessEnv>;
  private readonly connections = new Map<string, ExternalMcpConnection>();
  private closed = false;

  constructor(
    configuration: ExternalMcpConfiguration,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly connectionFactory: ExternalMcpConnectionFactory = createExternalMcpConnection,
  ) {
    this.servers = configuration.mcpServers;
    this.environment = environment;
  }

  async execute(
    request: ExternalMcpRequest,
    options?: ExternalMcpExecutionOptions,
  ): Promise<Result<ExternalMcpObservation, AnalysisError>> {
    if (isSignalAborted(options?.signal))
      return err(new AnalysisCancelledError(request.operation));
    if (this.closed)
      return err(
        new ProviderAdapterError("external-mcp", request.operation, {
          userMessage: "The external MCP bridge has been closed.",
        }),
      );

    try {
      switch (request.operation) {
        case "list_external_mcp_servers":
          return ok(
            createExternalMcpObservation(
              {
                configured: Object.keys(this.servers).length > 0,
                servers: Object.entries(this.servers).map(
                  ([serverId, registration]) => ({
                    server_id: serverId,
                    name: registration.name ?? serverId,
                    transport: registration.type,
                    allowed_tools: [...registration.allowedTools],
                    timeout_ms: registration.timeoutMs,
                  }),
                ),
              },
              bridgeIdentity(),
              {
                limitations: [
                  "This operation lists local configuration only; it does not start or contact any external server.",
                ],
              },
            ),
          );
        case "inspect_external_mcp_tools":
          return await this.#inspectTools(request.input, options);
        case "call_external_mcp_tool":
          return await this.#callTool(request.input, options);
      }
    } catch (cause: unknown) {
      if (isSignalAborted(options?.signal))
        return err(new AnalysisCancelledError(request.operation, { cause }));
      if (isAnalysisError(cause)) return err(cause);
      return err(
        new ProviderAdapterError("external-mcp", request.operation, {
          cause,
          userMessage:
            "The configured external MCP server could not complete the request. Check its local server configuration and availability.",
        }),
      );
    }
  }

  async close(): Promise<void> {
    if (this.closed && this.connections.size === 0) return;
    this.closed = true;
    const entries = [...this.connections.entries()];
    const results = await Promise.allSettled(
      entries.map(([, connection]) => connection.close()),
    );
    const failures: unknown[] = [];
    results.forEach((result, index) => {
      const entry = entries[index];
      if (entry === undefined) return;
      if (result.status === "fulfilled") {
        if (this.connections.get(entry[0]) === entry[1])
          this.connections.delete(entry[0]);
      } else failures.push(result.reason);
    });
    if (failures.length > 0)
      throw new AggregateError(failures, "External MCP server cleanup failed");
  }

  async #inspectTools(
    input: Extract<
      ExternalMcpRequest,
      { operation: "inspect_external_mcp_tools" }
    >["input"],
    options?: ExternalMcpExecutionOptions,
  ): Promise<Result<ExternalMcpObservation, AnalysisError>> {
    const registration = this.#registration(
      input.server_id,
      "inspect_external_mcp_tools",
    );
    if (!registration.ok) return registration;
    const connected = await this.#connect(
      input.server_id,
      registration.value,
      options,
    );
    if (!connected.ok) return connected;
    const { connection, tools } = connected.value;
    const pageTools = tools.slice(input.offset, input.offset + input.limit);
    const page = pageTools.map((tool) =>
      describeTool(tool, registration.value.allowedTools),
    );
    const nextOffset = input.offset + page.length;
    const serverVersion = safeBoundedJson(
      connection.serverInfo(),
      MAX_METADATA_TEXT_BYTES,
    );
    const provider = externalProviderIdentity(
      input.server_id,
      registration.value.name ?? input.server_id,
      serverVersion.value,
    );
    return ok(
      createExternalMcpObservation(
        {
          server_id: input.server_id,
          server_name: registration.value.name ?? input.server_id,
          server_version: serverVersion.value,
          offset: input.offset,
          limit: input.limit,
          total_tools: tools.length,
          next_offset: nextOffset < tools.length ? nextOffset : null,
          tools: page,
        },
        provider,
        {
          limitations: [
            CONNECTED_SERVER_LIMITATION,
            ACTIVE_TARGET_LIMITATION,
            ...(serverVersion.omitted
              ? [
                  "Upstream server metadata exceeded the REA+ metadata cap and was omitted.",
                ]
              : []),
            ...(page.some((tool) => {
              const descriptor = asRecord(tool);
              return (
                descriptor?.input_schema_omitted === true ||
                descriptor?.output_schema_omitted === true ||
                descriptor?.annotations_omitted === true
              );
            })
              ? [
                  "One or more upstream JSON Schemas were omitted because they exceeded the REA+ discovery response cap.",
                ]
              : []),
          ],
        },
      ),
    );
  }

  async #callTool(
    input: Extract<
      ExternalMcpRequest,
      { operation: "call_external_mcp_tool" }
    >["input"],
    options?: ExternalMcpExecutionOptions,
  ): Promise<Result<ExternalMcpObservation, AnalysisError>> {
    const registration = this.#registration(
      input.server_id,
      "call_external_mcp_tool",
    );
    if (!registration.ok) return registration;
    if (!registration.value.allowedTools.includes(input.tool_name))
      return err(
        new AnalysisCapabilityUnavailableError(
          `external-mcp:${input.server_id}`,
          "call_external_mcp_tool",
          "The requested upstream tool is not in this server's explicit allowedTools list.",
          {
            userMessage:
              "That upstream MCP tool is not allowlisted. Add its exact name to the local server registration before calling it.",
          },
        ),
      );

    const connected = await this.#connect(
      input.server_id,
      registration.value,
      options,
    );
    if (!connected.ok) return connected;
    const tool = connected.value.tools.find(
      (candidate) => candidate.name === input.tool_name,
    );
    if (tool === undefined)
      return err(
        new AnalysisCapabilityUnavailableError(
          `external-mcp:${input.server_id}`,
          "call_external_mcp_tool",
          "The configured upstream server did not advertise the allowlisted tool.",
          {
            userMessage:
              "The configured upstream server no longer advertises this allowlisted tool. Inspect its current tool list and configuration.",
          },
        ),
      );

    const serializedArguments = JSON.stringify(input.arguments);
    const argumentBytes = Buffer.byteLength(serializedArguments ?? "");
    if (argumentBytes > MAX_INPUT_ARGUMENT_BYTES)
      return err(
        new AnalysisInputError("call_external_mcp_tool", {
          cause: new Error(
            "External MCP arguments exceed the 64 KiB bridge limit",
          ),
        }),
      );
    const inputValidation = validateUpstreamArguments(tool, input.arguments);
    if (!inputValidation.ok) return inputValidation;

    const response = await connected.value.connection.call(
      input.tool_name,
      input.arguments,
      options?.signal,
    );
    const projection = projectCallToolResult(response);
    const serverVersion = safeBoundedJson(
      connected.value.connection.serverInfo(),
      MAX_METADATA_TEXT_BYTES,
    );
    const provider = externalProviderIdentity(
      input.server_id,
      registration.value.name ?? input.server_id,
      serverVersion.value,
    );
    return ok(
      createExternalMcpObservation(
        {
          server_id: input.server_id,
          server_name: registration.value.name ?? input.server_id,
          server_version: serverVersion.value,
          tool_name: input.tool_name,
          upstream_is_error: response.isError === true,
          structured_content: projection.structuredContent.value,
          structured_content_bytes: projection.structuredContent.bytes,
          structured_content_omitted: projection.structuredContent.omitted,
          content: projection.content.items,
          omitted_content_count: projection.content.omittedCount,
          limitations: [
            ...projection.limitations,
            ...(serverVersion.omitted
              ? [
                  "Upstream server metadata exceeded the REA+ metadata cap and was omitted.",
                ]
              : []),
          ],
        },
        provider,
        {
          limitations: [
            CONNECTED_SERVER_LIMITATION,
            ACTIVE_TARGET_LIMITATION,
            ...(serverVersion.omitted
              ? [
                  "Upstream server metadata exceeded the REA+ metadata cap and was omitted.",
                ]
              : []),
            RESPONSE_LIMITATION,
            "The caller's MCP arguments are represented in Evidence by their canonical SHA-256 digest and byte length, not stored verbatim; the upstream may still echo input values in its response.",
            ...projection.limitations,
          ],
        },
      ),
    );
  }

  #registration(
    serverId: string,
    operation: ExternalMcpOperation,
  ): Result<ExternalMcpRegistration, AnalysisError> {
    const registration = this.servers[serverId];
    if (registration === undefined)
      return err(
        new AnalysisCapabilityUnavailableError(
          "external-mcp",
          operation,
          "The requested server is not configured in REA_EXTERNAL_MCP_CONFIG.",
          {
            userMessage:
              "No external MCP server is configured with that ID. Configure a local MCP server before using this operation.",
          },
        ),
      );
    return ok(registration);
  }

  async #connect(
    serverId: string,
    registration: ExternalMcpRegistration,
    options?: ExternalMcpExecutionOptions,
  ): Promise<
    Result<
      {
        readonly connection: ExternalMcpConnection;
        readonly tools: readonly ExternalMcpTool[];
      },
      AnalysisError
    >
  > {
    if (isSignalAborted(options?.signal))
      return err(new AnalysisCancelledError("external_mcp_connect"));
    let connection = this.connections.get(serverId);
    try {
      if (connection === undefined) {
        connection = this.connectionFactory(registration, this.environment);
        this.connections.set(serverId, connection);
      }
      const tools = await connection.discover(options?.signal);
      return ok({ connection, tools });
    } catch (cause: unknown) {
      if (this.connections.get(serverId) === connection)
        this.connections.delete(serverId);
      await connection?.close().catch(() => undefined);
      if (isSignalAborted(options?.signal))
        return err(
          new AnalysisCancelledError("external_mcp_connect", { cause }),
        );
      return err(
        new ProviderAdapterError(`external-mcp:${serverId}`, "connect", {
          cause,
          userMessage:
            "The configured external MCP server could not be reached. Verify the local process or loopback endpoint and retry.",
        }),
      );
    }
  }
}

/** Application adapter returns a conservative identity for local config-only observations. */
const bridgeIdentity = (): ExternalMcpProviderIdentity => ({
  id: "rea-external-mcp-bridge",
  name: "REA+ External MCP Bridge",
  version: PRODUCT_IDENTITY.packageVersion,
});

const externalProviderIdentity = (
  serverId: string,
  configuredName: string,
  version: JsonValue | null,
): ExternalMcpProviderIdentity => ({
  id: `external-mcp:${serverId}`,
  name: `External MCP: ${configuredName}`,
  version:
    version !== null &&
    typeof version === "object" &&
    !Array.isArray(version) &&
    typeof version.version === "string"
      ? version.version
      : null,
});

const createExternalMcpObservation = (
  result: unknown,
  provider: ExternalMcpProviderIdentity,
  options: { readonly limitations?: readonly string[] } = {},
): ExternalMcpObservation => ({
  result: jsonValueSchema.parse(result),
  provider,
  limitations: [...(options.limitations ?? [])],
});

const describeTool = (
  tool: ExternalMcpTool,
  allowedTools: readonly string[],
): JsonValue => {
  const inputSchema = safeBoundedJson(tool.inputSchema, MAX_SCHEMA_BYTES);
  const outputSchema = safeBoundedJson(tool.outputSchema, MAX_SCHEMA_BYTES);
  const annotations = safeBoundedJson(
    tool.annotations ?? null,
    MAX_SCHEMA_BYTES,
  );
  const description =
    typeof tool.description === "string"
      ? boundedText(tool.description, MAX_TOOL_DESCRIPTION_BYTES)
      : { text: null, truncated: false };
  return jsonValueSchema.parse({
    name: boundedText(tool.name, MAX_METADATA_TEXT_BYTES).text,
    title:
      typeof tool.title === "string"
        ? boundedText(tool.title, MAX_METADATA_TEXT_BYTES).text
        : null,
    description: description.text,
    description_truncated: description.truncated,
    input_schema: inputSchema.value,
    output_schema: outputSchema.value,
    annotations: annotations.value,
    annotations_bytes: annotations.bytes,
    annotations_omitted: annotations.omitted,
    allowed: allowedTools.includes(tool.name),
    input_schema_bytes: inputSchema.bytes,
    input_schema_omitted: inputSchema.omitted,
    output_schema_bytes: outputSchema.bytes,
    output_schema_omitted: outputSchema.omitted,
  });
};

const validateUpstreamArguments = (
  tool: ExternalMcpTool,
  args: Readonly<Record<string, JsonValue>>,
): Result<null, AnalysisError> => {
  const schema = jsonValueSchema.safeParse(tool.inputSchema);
  if (
    !schema.success ||
    schema.data === null ||
    typeof schema.data !== "object" ||
    Array.isArray(schema.data)
  )
    return err(
      new ProviderAdapterError("external-mcp", "validate_tool_arguments", {
        userMessage:
          "The upstream MCP tool did not provide a usable JSON object input schema, so REA+ refused to call it.",
      }),
    );

  try {
    const validator = new Ajv2020({
      allErrors: false,
      ownProperties: true,
      strict: false,
      validateFormats: false,
    }).compile(schema.data as AnySchema);
    if (!validator(args))
      return err(
        new AnalysisInputError("call_external_mcp_tool", {
          cause: new Error(
            "Arguments do not satisfy the upstream tool input schema",
          ),
        }),
      );
    return ok(null);
  } catch (cause: unknown) {
    return err(
      new ProviderAdapterError("external-mcp", "validate_tool_arguments", {
        cause,
        userMessage:
          "The upstream MCP tool published an unsupported input schema, so REA+ refused to call it.",
      }),
    );
  }
};

const projectCallToolResult = (response: ExternalMcpCallResult) => {
  const structuredContent = safeBoundedJson(
    response.structuredContent ?? null,
    MAX_STRUCTURED_CONTENT_BYTES,
  );
  let remainingTextBytes = MAX_CONTENT_TOTAL_TEXT_BYTES;
  const items: JsonValue[] = [];
  const content = Array.isArray(response.content) ? response.content : [];
  const retainedItemCount = Math.min(content.length, MAX_CONTENT_ITEMS);
  let omittedCount = content.length - retainedItemCount;
  for (let index = 0; index < retainedItemCount; index += 1) {
    const block = content[index];
    const projected = projectContentBlock(block, remainingTextBytes);
    remainingTextBytes -= projected.textBytes;
    if (projected.omitted) omittedCount += 1;
    items.push(projected.value);
  }
  const limitations = [
    ...(structuredContent.omitted
      ? [
          "Structured upstream output exceeded the 64 KiB REA+ bridge cap and was omitted; its measured serialized byte length is retained.",
        ]
      : []),
    ...(omittedCount > 0
      ? [
          "Some upstream content was omitted or represented by metadata because of REA+ content/count limits or because it was non-text binary data.",
        ]
      : []),
  ];
  return {
    structuredContent,
    content: { items, omittedCount },
    limitations,
  };
};

const projectContentBlock = (
  block: unknown,
  remainingTextBytes: number,
): {
  readonly value: JsonValue;
  readonly textBytes: number;
  readonly omitted: boolean;
} => {
  const record = asRecord(block);
  const type = typeof record?.type === "string" ? record.type : "unknown";
  const base: Record<string, JsonValue> = { type };

  if (typeof record?.text === "string") {
    const text = boundedText(
      record.text,
      Math.min(MAX_CONTENT_TEXT_BYTES, remainingTextBytes),
    );
    base.text = text.text;
    base.text_truncated = text.truncated;
    return {
      value: jsonValueSchema.parse(base),
      textBytes: text.bytes,
      omitted: text.truncated,
    };
  }

  if (typeof record?.mimeType === "string")
    base.mime_type = boundedText(record.mimeType, MAX_METADATA_TEXT_BYTES).text;
  if (typeof record?.uri === "string")
    base.uri = boundedText(record.uri, MAX_METADATA_TEXT_BYTES).text;
  if (typeof record?.name === "string")
    base.name = boundedText(record.name, MAX_METADATA_TEXT_BYTES).text;
  if (typeof record?.description === "string")
    base.description = boundedText(
      record.description,
      MAX_METADATA_TEXT_BYTES,
    ).text;

  const resource = asRecord(record?.resource);
  if (resource !== undefined) {
    if (typeof resource.uri === "string")
      base.uri = boundedText(resource.uri, MAX_METADATA_TEXT_BYTES).text;
    if (typeof resource.mimeType === "string")
      base.mime_type = boundedText(
        resource.mimeType,
        MAX_METADATA_TEXT_BYTES,
      ).text;
    if (typeof resource.text === "string") {
      const text = boundedText(
        resource.text,
        Math.min(MAX_CONTENT_TEXT_BYTES, remainingTextBytes),
      );
      base.text = text.text;
      base.text_truncated = text.truncated;
      return {
        value: jsonValueSchema.parse(base),
        textBytes: text.bytes,
        omitted: text.truncated,
      };
    }
    const blobBytes = base64ByteLength(resource.blob);
    if (blobBytes !== null) base.byte_length = blobBytes;
  }

  const binaryBytes = base64ByteLength(record?.data);
  if (binaryBytes !== null) base.byte_length = binaryBytes;
  const omitted = binaryBytes !== null || resource?.blob !== undefined;
  if (omitted) base.omitted = true;
  if (record?.annotations !== undefined) base.annotations_omitted = true;
  return {
    value: jsonValueSchema.parse(base),
    textBytes: 0,
    omitted,
  };
};

const safeBoundedJson = (
  value: unknown,
  maximumBytes: number,
): {
  readonly value: JsonValue | null;
  readonly bytes: number;
  readonly omitted: boolean;
} => {
  if (value === null || value === undefined)
    return { value: null, bytes: 0, omitted: false };
  const parsed = jsonValueSchema.safeParse(value);
  if (!parsed.success) return { value: null, bytes: 0, omitted: true };
  const encoded = JSON.stringify(parsed.data);
  if (encoded === undefined) return { value: null, bytes: 0, omitted: true };
  const bytes = Buffer.byteLength(encoded);
  return bytes <= maximumBytes
    ? { value: parsed.data, bytes, omitted: false }
    : { value: null, bytes, omitted: true };
};

const boundedText = (
  value: string,
  maximumBytes: number,
): {
  readonly text: string;
  readonly bytes: number;
  readonly truncated: boolean;
} => {
  const fullBytes = Buffer.byteLength(value);
  if (fullBytes <= maximumBytes)
    return { text: value, bytes: fullBytes, truncated: false };
  const chunks: string[] = [];
  let bytes = 0;
  for (const codePoint of value) {
    const codePointBytes = Buffer.byteLength(codePoint);
    if (bytes + codePointBytes > maximumBytes) break;
    chunks.push(codePoint);
    bytes += codePointBytes;
  }
  return { text: chunks.join(""), bytes, truncated: true };
};

const base64ByteLength = (value: unknown): number | null => {
  if (typeof value !== "string") return null;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((value.length * 3) / 4) - padding);
};

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

const isSignalAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

const isAnalysisError = (value: unknown): value is AnalysisError =>
  value instanceof Error && "_tag" in value;
