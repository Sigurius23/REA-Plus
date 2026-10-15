import type {
  ExternalMcpCallResult,
  ExternalMcpConnection,
  ExternalMcpTool,
} from "../../src/externalMcp/ExternalMcpConnection.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";

export type BinaryNinjaToolSchema = {
  readonly type: "object";
  readonly properties: Readonly<Record<string, unknown>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
};

export const binaryNinjaSchema = (
  properties: Readonly<Record<string, unknown>> = {},
  required: readonly string[] = [],
): BinaryNinjaToolSchema => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});

const stringProperty = { type: "string" };
const numberProperty = { type: "integer", minimum: 0 };
const functionPageOutputSchema = {
  type: "object",
  properties: {
    functions: {
      type: "array",
      items: {
        type: "object",
        properties: {
          address: stringProperty,
          name: stringProperty,
          arch: stringProperty,
        },
        required: ["address", "name"],
        additionalProperties: true,
      },
    },
    count: numberProperty,
    total: numberProperty,
    nextOffset: {
      anyOf: [numberProperty, { type: "null" }],
    },
    truncated: { type: "boolean" },
  },
  required: ["functions", "count", "total", "nextOffset", "truncated"],
  additionalProperties: true,
};
const stringPageOutputSchema = {
  ...functionPageOutputSchema,
  properties: {
    ...functionPageOutputSchema.properties,
    strings: {
      type: "array",
      items: {
        type: "object",
        properties: { address: stringProperty, value: stringProperty },
        required: ["address", "value"],
        additionalProperties: true,
      },
    },
  },
  required: ["strings", "count", "total", "nextOffset", "truncated"],
};
export const BINARY_NINJA_FIXTURE_TOOLS: readonly ExternalMcpTool[] = [
  { name: "bn_open_item_list", inputSchema: binaryNinjaSchema() },
  {
    name: "bn_open_item_open",
    inputSchema: binaryNinjaSchema({ path: stringProperty }, ["path"]),
  },
  {
    name: "bn_binary_view_list",
    inputSchema: binaryNinjaSchema({ openItem: stringProperty }, ["openItem"]),
  },
  {
    name: "bn_binary_view_set_active",
    inputSchema: binaryNinjaSchema({ binaryView: stringProperty }, [
      "binaryView",
    ]),
  },
  { name: "bn_binary_overview", inputSchema: binaryNinjaSchema() },
  {
    name: "bn_function_list",
    inputSchema: binaryNinjaSchema(
      {
        offset: numberProperty,
        limit: numberProperty,
        binaryView: stringProperty,
      },
      ["offset", "limit", "binaryView"],
    ),
    outputSchema: functionPageOutputSchema,
  },
  {
    name: "bn_string_list",
    inputSchema: binaryNinjaSchema(
      {
        offset: numberProperty,
        limit: numberProperty,
        binaryView: stringProperty,
      },
      ["offset", "limit", "binaryView"],
    ),
    outputSchema: stringPageOutputSchema,
  },
  {
    name: "bn_function_decompile",
    inputSchema: binaryNinjaSchema(
      { function: stringProperty, binaryView: stringProperty },
      ["function", "binaryView"],
    ),
  },
  {
    name: "bn_function_disassembly",
    inputSchema: binaryNinjaSchema(
      { function: stringProperty, binaryView: stringProperty },
      ["function", "binaryView"],
    ),
  },
];

/** Test-owned recorder for the official handle, view, and read-only tool contract. */
export class RecordingBinaryNinja implements ExternalMcpConnection {
  readonly calls: {
    readonly name: string;
    readonly args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  closed = false;
  opened = false;

  constructor(
    private readonly path: string,
    private readonly sha256: string,
  ) {}

  async connect() {
    return BINARY_NINJA_FIXTURE_TOOLS;
  }

  async discover() {
    return BINARY_NINJA_FIXTURE_TOOLS;
  }

  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<ExternalMcpCallResult> {
    this.calls.push({ name, args: structuredClone(args) });
    let result: JsonValue;
    switch (name) {
      case "bn_open_item_list":
        result = {
          openItems: this.opened
            ? [{ openItem: "open-item-1", path: this.path }]
            : [],
        };
        break;
      case "bn_open_item_open":
        this.opened = true;
        result = { result: { openItem: "open-item-1", path: this.path } };
        break;
      case "bn_binary_view_list":
        result = {
          binaryViews: [
            {
              binaryView: "binary-view-1",
              recommended: true,
              available: true,
              viewType: "ELF",
            },
          ],
        };
        break;
      case "bn_binary_view_set_active":
        result = { active: true };
        break;
      case "bn_binary_overview":
        result = {
          path: this.path,
          sha256: this.sha256,
          imageBase: "0x400000",
        };
        break;
      case "bn_function_list":
        result = {
          functions: [{ address: "0x401000", name: "main" }],
          count: 1,
          total: 1,
          nextOffset: null,
          truncated: false,
        };
        break;
      case "bn_string_list":
        result = {
          strings: [{ address: "0x402000", value: "license check" }],
          count: 1,
          total: 1,
          nextOffset: null,
          truncated: false,
        };
        break;
      case "bn_function_decompile":
        result = { pseudocode: "int main(void) { return 42; }" };
        break;
      case "bn_function_disassembly":
        result = {
          lines: [{ address: "0x401000", instruction: "ret" }],
        };
        break;
      default:
        throw new Error(`Unexpected Binary Ninja tool: ${name}`);
    }
    return { structuredContent: result };
  }

  serverInfo(): JsonValue {
    return { name: "binaryninja-mcp", version: "fixture" };
  }

  async close() {
    this.closed = true;
  }
}
