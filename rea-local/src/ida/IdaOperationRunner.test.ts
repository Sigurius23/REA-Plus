import { describe, expect, it } from "vitest";

import type { JsonValue } from "../domain/jsonValue.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { IdaOperationRunner } from "./IdaOperationRunner.js";

type Inventory = "functions" | "strings";

const oneFunction: JsonValue = {
  address: "0x1000",
  name: "main",
  size: "0x10",
};
const oneString: JsonValue = {
  address: "0x2000",
  string: "hello",
  length: 5,
};

const createConnection = (
  inventory: Inventory,
  page: (offset: number) => JsonValue,
): { readonly connection: IdaMcpConnection; readonly calls: () => number } => {
  let calls = 0;
  const expectedTool =
    inventory === "functions" ? "list_functions" : "list_strings";
  const connection: IdaMcpConnection = {
    connect: async () => [],
    call: async (name, args) => {
      if (name !== expectedTool)
        throw new Error(`Unexpected IDA tool call: ${name}`);
      if (typeof args.offset !== "number")
        throw new Error("IDA inventory request omitted its numeric offset");
      calls += 1;
      return page(args.offset);
    },
    serverInfo: () => null,
    close: async () => undefined,
  };
  return { connection, calls: () => calls };
};

const runInventory = (runner: IdaOperationRunner, inventory: Inventory) =>
  inventory === "functions" ? runner.functions() : runner.strings();

describe("IDA inventory safety limits", () => {
  it.each(["functions", "strings"] as const)(
    "stops %s after the page safety cap",
    async (inventory) => {
      const fixture = createConnection(inventory, (offset) => ({
        data: [inventory === "functions" ? oneFunction : oneString],
        next_offset: offset + 1,
      }));
      const runner = new IdaOperationRunner(fixture.connection, "legacy");

      await expect(runInventory(runner, inventory)).rejects.toThrow(
        "pagination-page safety cap",
      );
      expect(fixture.calls()).toBe(2_048);
    },
  );

  it.each(["functions", "strings"] as const)(
    "rejects %s inventories above the item safety cap",
    async (inventory) => {
      const row = inventory === "functions" ? oneFunction : oneString;
      const rows = Array.from({ length: 100_001 }, () => row);
      const fixture = createConnection(inventory, () => ({
        data: rows,
        next_offset: null,
      }));
      const runner = new IdaOperationRunner(fixture.connection, "legacy");

      await expect(runInventory(runner, inventory)).rejects.toThrow(
        "100,000-item safety cap",
      );
      expect(fixture.calls()).toBe(1);
    },
  );
});
