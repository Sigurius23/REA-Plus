import { describe, expect, it } from "vitest";

import type { JsonValue } from "../domain/jsonValue.js";
import type { ExternalMcpTool } from "../externalMcp/ExternalMcpConnection.js";
import { BinaryNinjaOperationRunner } from "./BinaryNinjaOperations.js";
import type { ToolRole } from "./BinaryNinjaMcpArguments.js";

type Inventory = "functions" | "strings";

const stringSchema = { type: "string" } as const;
const integerSchema = { type: "integer", minimum: 0 } as const;

const inventoryTool = (
  name: string,
  inventory: Inventory,
  inputProperties: Readonly<Record<string, unknown>> = {
    binaryView: stringSchema,
    offset: integerSchema,
    limit: integerSchema,
  },
  additionalProperties = false,
  includeOutputSchema = true,
): ExternalMcpTool => ({
  name,
  inputSchema: {
    type: "object",
    properties: inputProperties,
    additionalProperties,
  },
  ...(includeOutputSchema
    ? {
        outputSchema: {
          type: "object",
          properties: {
            [inventory]: {
              type: "array",
              items: {
                type: "object",
                properties:
                  inventory === "functions"
                    ? {
                        address: stringSchema,
                        name: stringSchema,
                        arch: stringSchema,
                      }
                    : { address: stringSchema, value: stringSchema },
                required:
                  inventory === "functions"
                    ? ["address", "name"]
                    : ["address", "value"],
                additionalProperties: true,
              },
            },
            count: integerSchema,
            total: integerSchema,
            nextOffset: {
              anyOf: [integerSchema, { type: "null" }],
            },
            truncated: { type: "boolean" },
          },
          required: [inventory, "count", "total", "nextOffset", "truncated"],
          additionalProperties: true,
        },
      }
    : {}),
});

const page = (
  inventory: Inventory,
  rows: JsonValue[],
  metadata: {
    readonly count?: number;
    readonly total: number;
    readonly nextOffset: number | null;
    readonly truncated: boolean;
  },
): JsonValue => ({
  [inventory]: rows,
  count: metadata.count ?? rows.length,
  total: metadata.total,
  nextOffset: metadata.nextOffset,
  truncated: metadata.truncated,
});

const createRunner = (
  role: ToolRole,
  tool: ExternalMcpTool,
  invoke: (args: Readonly<Record<string, JsonValue>>) => Promise<JsonValue>,
) => {
  const calls: Readonly<Record<string, JsonValue>>[] = [];
  const runner = new BinaryNinjaOperationRunner(
    new Map([[role, tool.name]]),
    () => tool,
    async (_name, args) => {
      calls.push(structuredClone(args));
      return invoke(args);
    },
    () => "binary-view-1",
  );
  return { runner, calls };
};

describe("Binary Ninja normalized inventory pagination: schema-aware offsets", () => {
  it.each([
    {
      role: "functions" as const,
      operation: "list_procedures" as const,
      toolName: "bn_function_list",
      inventory: "functions" as const,
      first: { address: "0x10", name: "alpha" },
      second: { address: "0x20", name: "beta" },
      expected: [
        { address: "0x10", value: "alpha" },
        { address: "0x20", value: "beta" },
      ],
    },
    {
      role: "strings" as const,
      operation: "list_strings" as const,
      toolName: "bn_string_list",
      inventory: "strings" as const,
      first: { address: "0x10", value: "alpha" },
      second: { address: "0x20", value: "beta" },
      expected: [
        { address: "0x10", value: "alpha" },
        { address: "0x20", value: "beta" },
      ],
    },
  ])(
    "follows the documented $inventory offset/limit contract and validates both pages",
    async ({
      role,
      operation,
      toolName,
      inventory,
      first,
      second,
      expected,
    }) => {
      const tool = inventoryTool(toolName, inventory);
      const { runner, calls } = createRunner(role, tool, async (args) =>
        args.offset === 0
          ? page(inventory, [first], {
              total: 2,
              nextOffset: 1,
              truncated: true,
            })
          : page(inventory, [second], {
              total: 2,
              nextOffset: null,
              truncated: false,
            }),
      );

      await expect(runner.execute(operation, {})).resolves.toEqual(expected);
      expect(calls).toEqual([
        { offset: 0, limit: 500, binaryView: "binary-view-1" },
        { offset: 1, limit: 500, binaryView: "binary-view-1" },
      ]);
    },
  );

  it.each([
    {
      role: "functions" as const,
      operation: "list_procedures" as const,
      toolName: "bn_function_list",
      inventory: "functions" as const,
      rows: [{ address: "0x10", name: "alpha" }],
    },
    {
      role: "strings" as const,
      operation: "list_strings" as const,
      toolName: "bn_string_list",
      inventory: "strings" as const,
      rows: [{ address: "0x10", value: "alpha" }],
    },
  ])(
    "rejects $inventory continuation when the input schema does not advertise offset",
    async ({ role, operation, toolName, inventory, rows }) => {
      const tool = inventoryTool(
        toolName,
        inventory,
        { binaryView: stringSchema, limit: integerSchema },
        true,
      );
      const { runner, calls } = createRunner(role, tool, async () =>
        page(inventory, rows, {
          total: 2,
          nextOffset: 1,
          truncated: true,
        }),
      );

      await expect(runner.execute(operation, {})).rejects.toThrow(
        "does not advertise the documented offset field",
      );
      expect(calls).toEqual([{ limit: 500, binaryView: "binary-view-1" }]);
    },
  );

  it("does not infer an inventory row schema when the server omits outputSchema", async () => {
    const tool = inventoryTool(
      "bn_function_list",
      "functions",
      undefined,
      false,
      false,
    );
    const { runner } = createRunner("functions", tool, async () =>
      page("functions", [{ address: "0x10", name: "alpha" }], {
        total: 1,
        nextOffset: null,
        truncated: false,
      }),
    );

    await expect(runner.execute("list_procedures", {})).rejects.toThrow(
      "did not advertise an output schema",
    );
  });
});

describe("Binary Ninja normalized inventory pagination: response metadata", () => {
  it.each([
    {
      name: "non-advancing offset",
      result: (inventory: Inventory) =>
        page(
          inventory,
          [
            inventory === "functions"
              ? { address: "0x10", name: "alpha" }
              : { address: "0x10", value: "alpha" },
          ],
          { total: 2, nextOffset: 0, truncated: true },
        ),
      message: "exact advancing offset",
    },
    {
      name: "count mismatch",
      result: (inventory: Inventory) =>
        page(
          inventory,
          [
            inventory === "functions"
              ? { address: "0x10", name: "alpha" }
              : { address: "0x10", value: "alpha" },
          ],
          { count: 2, total: 2, nextOffset: null, truncated: false },
        ),
      message: "count does not match",
    },
    {
      name: "incomplete terminal page",
      result: (inventory: Inventory) =>
        page(
          inventory,
          [
            inventory === "functions"
              ? { address: "0x10", name: "alpha" }
              : { address: "0x10", value: "alpha" },
          ],
          { total: 2, nextOffset: null, truncated: false },
        ),
      message: "marked an inventory complete before its reported total",
    },
  ])("rejects $name metadata for an inventory", async ({ result, message }) => {
    const inventory = "functions" as const;
    const tool = inventoryTool("bn_function_list", inventory);
    const { runner } = createRunner("functions", tool, async () =>
      result(inventory),
    );

    await expect(runner.execute("list_procedures", {})).rejects.toThrow(
      message,
    );
  });

  it("rejects a changing total and duplicate rows across pages", async () => {
    const tool = inventoryTool("bn_function_list", "functions");
    let call = 0;
    const { runner } = createRunner("functions", tool, async () => {
      call += 1;
      return call === 1
        ? page("functions", [{ address: "0x10", name: "alpha" }], {
            total: 2,
            nextOffset: 1,
            truncated: true,
          })
        : page("functions", [{ address: "0x10", name: "alpha" }], {
            total: 2,
            nextOffset: null,
            truncated: false,
          });
    });

    await expect(runner.execute("list_procedures", {})).rejects.toThrow(
      "duplicate address and architecture",
    );

    const changedTotal = createRunner("functions", tool, async (args) =>
      args.offset === 0
        ? page("functions", [{ address: "0x10", name: "alpha" }], {
            total: 2,
            nextOffset: 1,
            truncated: true,
          })
        : page(
            "functions",
            [
              { address: "0x20", name: "beta" },
              { address: "0x30", name: "gamma" },
            ],
            { total: 3, nextOffset: null, truncated: false },
          ),
    );
    await expect(
      changedTotal.runner.execute("list_procedures", {}),
    ).rejects.toThrow("total changed during pagination");
  });
});

describe("Binary Ninja normalized inventory pagination: aggregate safety caps", () => {
  it.each([
    {
      role: "functions" as const,
      operation: "list_procedures" as const,
      toolName: "bn_function_list",
      inventory: "functions" as const,
      row: { address: "0x10", name: "alpha" },
    },
    {
      role: "strings" as const,
      operation: "list_strings" as const,
      toolName: "bn_string_list",
      inventory: "strings" as const,
      row: { address: "0x10", value: "alpha" },
    },
  ])(
    "rejects $inventory totals above the item safety cap",
    async (testCase) => {
      const tool = inventoryTool(testCase.toolName, testCase.inventory);
      const { runner, calls } = createRunner(testCase.role, tool, async () =>
        page(testCase.inventory, [testCase.row], {
          total: 100_001,
          nextOffset: 1,
          truncated: true,
        }),
      );

      await expect(runner.execute(testCase.operation, {})).rejects.toThrow(
        "100,000-item safety cap",
      );
      expect(calls).toHaveLength(1);
    },
  );

  it.each([
    {
      role: "functions" as const,
      operation: "list_procedures" as const,
      toolName: "bn_function_list",
      inventory: "functions" as const,
      row: { address: "0x10", name: "alpha" },
    },
    {
      role: "strings" as const,
      operation: "list_strings" as const,
      toolName: "bn_string_list",
      inventory: "strings" as const,
      row: { address: "0x10", value: "alpha" },
    },
  ])("stops paginating $inventory at the page safety cap", async (testCase) => {
    const tool = inventoryTool(testCase.toolName, testCase.inventory);
    const { runner, calls } = createRunner(
      testCase.role,
      tool,
      async (args) => {
        const offset = args.offset;
        if (typeof offset !== "number")
          throw new Error("Binary Ninja request omitted its offset");
        return page(testCase.inventory, [testCase.row], {
          total: 3_000,
          nextOffset: offset + 1,
          truncated: true,
        });
      },
    );

    await expect(runner.execute(testCase.operation, {})).rejects.toThrow(
      "pagination-page safety cap",
    );
    expect(calls).toHaveLength(2_048);
  });
});
