import { z } from "zod";

import { jsonValueSchema } from "../jsonValue.js";

export const externalMcpServerIdSchema = z
  .string()
  .regex(/^[a-z][a-z0-9\-]{0,63}$/u);

export const externalMcpInputSchemas = {
  list_external_mcp_servers: z.strictObject({}),
  inspect_external_mcp_tools: z.strictObject({
    server_id: externalMcpServerIdSchema,
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(100).default(25),
  }),
  call_external_mcp_tool: z.strictObject({
    server_id: externalMcpServerIdSchema,
    tool_name: z.string().min(1).max(256),
    arguments: z.record(z.string(), jsonValueSchema).default({}),
  }),
} as const;

export type ExternalMcpOperation = keyof typeof externalMcpInputSchemas;

const serverDescriptor = z.strictObject({
  server_id: externalMcpServerIdSchema,
  name: z.string().min(1),
  transport: z.enum(["stdio", "http"]),
  allowed_tools: z.array(z.string()),
  timeout_ms: z.number().int().positive(),
});

const toolDescriptor = z.strictObject({
  name: z.string().min(1),
  title: z.string().nullable(),
  description: z.string().nullable(),
  description_truncated: z.boolean(),
  input_schema: jsonValueSchema.nullable(),
  output_schema: jsonValueSchema.nullable(),
  annotations: jsonValueSchema.nullable(),
  annotations_bytes: z.number().int().min(0),
  annotations_omitted: z.boolean(),
  allowed: z.boolean(),
  input_schema_bytes: z.number().int().min(0),
  input_schema_omitted: z.boolean(),
  output_schema_bytes: z.number().int().min(0),
  output_schema_omitted: z.boolean(),
});

const contentItem = z.strictObject({
  type: z.string().min(1),
  text: z.string().optional(),
  text_truncated: z.boolean().optional(),
  mime_type: z.string().optional(),
  uri: z.string().optional(),
  name: z.string().optional(),
  description: z.string().optional(),
  byte_length: z.number().int().min(0).nullable().optional(),
  omitted: z.boolean().optional(),
  annotations_omitted: z.boolean().optional(),
});

export const externalMcpResultSchemas = {
  list_external_mcp_servers: z.strictObject({
    configured: z.boolean(),
    servers: z.array(serverDescriptor),
  }),
  inspect_external_mcp_tools: z.strictObject({
    server_id: externalMcpServerIdSchema,
    server_name: z.string().min(1),
    server_version: jsonValueSchema.nullable(),
    offset: z.number().int().min(0),
    limit: z.number().int().min(1).max(100),
    total_tools: z.number().int().min(0),
    next_offset: z.number().int().min(0).nullable(),
    tools: z.array(toolDescriptor),
  }),
  call_external_mcp_tool: z.strictObject({
    server_id: externalMcpServerIdSchema,
    server_name: z.string().min(1),
    server_version: jsonValueSchema.nullable(),
    tool_name: z.string().min(1),
    upstream_is_error: z.boolean(),
    structured_content: jsonValueSchema.nullable(),
    structured_content_bytes: z.number().int().min(0),
    structured_content_omitted: z.boolean(),
    content: z.array(contentItem),
    omitted_content_count: z.number().int().min(0),
    limitations: z.array(z.string()),
  }),
} satisfies Readonly<Record<ExternalMcpOperation, z.ZodType>>;

export const externalMcpRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("list_external_mcp_servers"),
    input: externalMcpInputSchemas.list_external_mcp_servers,
  }),
  z.strictObject({
    operation: z.literal("inspect_external_mcp_tools"),
    input: externalMcpInputSchemas.inspect_external_mcp_tools,
  }),
  z.strictObject({
    operation: z.literal("call_external_mcp_tool"),
    input: externalMcpInputSchemas.call_external_mcp_tool,
  }),
]);

export type ExternalMcpRequest = z.infer<typeof externalMcpRequestSchema>;
