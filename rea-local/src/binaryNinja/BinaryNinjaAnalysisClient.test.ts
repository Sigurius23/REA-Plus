import { rm } from "node:fs/promises";

import { afterEach, describe, expect, it } from "vitest";

import { BinaryNinjaAnalysisClient } from "./BinaryNinjaAnalysisClient.js";
import {
  BINARY_NINJA_FIXTURE_TOOLS,
  RecordingBinaryNinja,
} from "../../tests/fixtures/binaryNinjaMcp.js";
import { createIdaTarget } from "../../tests/fixtures/idaMcp.js";

describe("official Binary Ninja MCP normalized adapter", () => {
  const roots: string[] = [];
  afterEach(async () => {
    for (const root of roots.splice(0))
      await rm(root, { recursive: true, force: true });
  });

  it("binds an official open-item and BinaryView handle and normalizes read-only analysis", async () => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const upstream = new RecordingBinaryNinja(target.path, target.sha256);
    const client = new BinaryNinjaAnalysisClient(
      target,
      upstream,
      BINARY_NINJA_FIXTURE_TOOLS.map(({ name }) => name),
    );

    const procedures = await client.execute("list_procedures", {});
    expect(procedures.ok).toBe(true);
    if (!procedures.ok) throw procedures.error;
    expect(procedures.value.result).toEqual([
      { address: "0x401000", value: "main" },
    ]);
    expect(procedures.value.provider.id).toBe("binary-ninja");

    const pseudocode = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(pseudocode.ok).toBe(true);
    if (!pseudocode.ok) throw pseudocode.error;
    expect(pseudocode.value.result).toBe("int main(void) { return 42; }");
    expect(
      upstream.calls.find(({ name }) => name === "bn_function_decompile")?.args,
    ).toEqual({ function: "0x401000", binaryView: "binary-view-1" });

    const disassembly = await client.execute("procedure_assembly", {
      procedure: "0x401000",
    });
    expect(disassembly.ok).toBe(true);
    if (!disassembly.ok) throw disassembly.error;
    expect(disassembly.value.result).toBe("0x401000: ret");

    const strings = await client.execute("search_strings", {
      pattern: "LICENSE",
    });
    expect(strings.ok).toBe(true);
    if (!strings.ok) throw strings.error;
    expect(strings.value.result).toEqual([
      { address: "0x402000", value: "license check" },
    ]);

    expect(
      upstream.calls.some(({ name }) =>
        ["bn_open_item_save", "bn_open_item_close"].includes(name),
      ),
    ).toBe(false);
    expect((await client.close()).ok).toBe(true);
    expect(upstream.closed).toBe(true);
  });
});
