import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const text = z.string().nullable();

export const PROTOCOL_VIEWS = [
  "formats",
  "fields",
  "messages",
  "flows",
] as const;
export const PROTOCOL_FIELD_KINDS = [
  "type",
  "constant",
  "length",
  "counter",
  "checksum",
  "timestamp",
  "float",
  "text",
  "enum",
  "id",
  "bytes",
  "variable",
] as const;
export const PROTOCOL_PAGE_LIMIT = 1000;

export const inferProtocolFieldsInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute packet capture (PCAP or PCAPNG), or a text file with one message per line in hex",
    ),
  transport: z
    .enum(["auto", "udp", "tcp"])
    .default("auto")
    .describe("Which payloads to analyse: UDP datagrams, TCP streams, or both"),
  port: z
    .number()
    .int()
    .min(0)
    .max(65535)
    .optional()
    .describe("Keep flows with this source or destination port"),
  flow: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Keep flows whose key contains this text, e.g. 10.0.0.5:7777"),
  view: z
    .enum(PROTOCOL_VIEWS)
    .default("formats")
    .describe(
      "formats: message formats told apart by a type field; fields: each format's inferred fields; messages: messages with their format; flows: the flows analysed",
    ),
  format: count
    .optional()
    .describe("Format id whose fields or messages to list"),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of field kinds, details, samples or message hex",
    ),
  offset: count.default(0).describe("Matching rows to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(PROTOCOL_PAGE_LIMIT)
    .default(200)
    .describe("Matching rows to return"),
});

export const protocolFormatRowSchema = z.strictObject({
  id: count,
  key: text.describe(
    "The type value: hex bytes, or the first word of text messages.",
  ),
  key_offset: count.nullable(),
  key_width: count.nullable(),
  direction: z.enum(["a-to-b", "b-to-a"]).nullable(),
  messages: count,
  min_length: count,
  max_length: count,
  fields: count,
});

export const protocolFieldRowSchema = z.strictObject({
  format: count,
  offset: count,
  from: z
    .enum(["start", "end"])
    .describe(
      "A trailer in messages of different lengths counts from the end.",
    ),
  length: count
    .nullable()
    .describe("Null for the variable part after the fixed header."),
  kind: z.enum(PROTOCOL_FIELD_KINDS),
  encoding: text.describe("u8, u16le, u32be, f32le, ascii..."),
  detail: text,
  distinct: count,
  samples: z.array(z.string()),
});

export const protocolMessageRowSchema = z.strictObject({
  index: count,
  format: count,
  flow: z.string(),
  direction: z.enum(["a-to-b", "b-to-a"]).nullable(),
  time: z.number().nullable(),
  length: count,
  hex: z.string().describe("The first 64 bytes."),
});

export const protocolFlowRowSchema = z.strictObject({
  flow: z.string(),
  transport: z.enum(["udp", "tcp", "hex"]),
  messages: count,
  bytes: count,
});

export const protocolFieldsSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
  }),
  source: z.strictObject({
    format: z.enum(["pcap", "pcapng", "hex_lines"]),
    frames: count,
    analysed: count.describe("Messages the inference used: the first 5000."),
  }),
  framing: z.strictObject({
    kind: z.enum([
      "datagrams",
      "lines",
      "segments",
      "length_prefix",
      "delimiter",
    ]),
    offset: count.nullable(),
    width: count.nullable(),
    endian: z.enum(["little", "big"]).nullable(),
    adjust: z
      .number()
      .int()
      .nullable()
      .describe("Message length = prefix value + adjust."),
    delimiter: text,
  }),
  inference: z.strictObject({
    text: z.boolean(),
    byte_order: z.enum(["little", "big"]),
  }),
  summary: z.strictObject({
    messages: count,
    formats: count,
    fields: count,
    flows: count,
  }),
  page: z.strictObject({
    view: z.enum(PROTOCOL_VIEWS),
    format: count.nullable(),
    query: text,
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  formats: z.array(protocolFormatRowSchema),
  fields: z.array(protocolFieldRowSchema),
  messages: z.array(protocolMessageRowSchema),
  flows: z.array(protocolFlowRowSchema),
  limitations: z.array(z.string()),
});

export type InferProtocolFieldsInput = z.output<
  typeof inferProtocolFieldsInputSchema
>;
export type ProtocolFieldsReport = z.output<typeof protocolFieldsSchema>;
