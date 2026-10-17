import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BinaryDiffService } from "../../../../src/application/bindiff/BinaryDiffService.js";
import { BinaryDiffInspector } from "../../../../src/bindiff/BinaryDiffInspector.js";
import type { BinaryDiffReport } from "../../../../src/domain/bindiff/binaryDiff.js";
import { ok } from "../../../../src/domain/result.js";
import {
  fixtureBuilds,
  fixtureSession,
  type FixtureFunction,
} from "../../../fixtures/binaryDiffFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

let root = "";
let left = "";
let right = "";
let sessions = 0;
const digests = new Map<string, string>();
let builds = new Map<string, readonly FixtureFunction[]>();
let service: BinaryDiffService;

beforeAll(async () => {
  root = (await createTestWorkspace("rea-bindiff-")).root;
  left = join(root, "game-1.0");
  right = join(root, "game-1.1");
  for (const [path, bytes] of [
    [left, "build one"],
    [right, "build two"],
  ] as const) {
    await writeFile(path, bytes);
    digests.set(path, createHash("sha256").update(bytes).digest("hex"));
  }
  const { left: older, right: newer } = fixtureBuilds();
  builds = new Map([
    [left, older],
    [right, newer],
  ]);
  service = new BinaryDiffService(
    new BinaryDiffInspector(async () => {
      sessions += 1;
      return ok(
        fixtureSession(builds, (path) => digests.get(path) ?? "0".repeat(64)),
      );
    }),
  );
});
afterAll(async () => {
  await service.close();
  await removeTestWorkspace(root);
});

const diff = async (input: Record<string, unknown> = {}) => {
  const result = await service.inspect({ left, right, ...input });
  if (!result.ok) throw result.error;
  return result.value;
};
const report = async (input: Record<string, unknown> = {}) =>
  (await diff(input)).normalized_result as BinaryDiffReport;

describe("diff_binaries over a fixture provider", () => {
  it("matches moved, changed, removed and added functions", async () => {
    const evidence = await diff();
    expect(evidence.provider.id).toBe("binary-diff");
    expect(evidence.confidence).toBe("inferred");
    expect(evidence.subject).toMatchObject({
      name: "game-1.1",
      digest: { sha256: digests.get(right) },
      format: "elf",
    });
    const summary = evidence.normalized_result as BinaryDiffReport;
    expect(summary.left).toMatchObject({
      analysis_provider: "fixture-provider",
      functions_listed: 10,
      functions_analyzed: 10,
      functions_failed: 0,
      truncated: false,
    });
    expect(summary.summary).toMatchObject({
      matched: 9,
      identical: 8,
      changed: 1,
      removed: 1,
      added: 1,
    });
    // update: a larger constant, and a call to the new function.
    expect(summary.functions).toEqual([
      expect.objectContaining({
        left: { address: "0x1300", name: "fcn.00001300" },
        right: { address: "0x1340", name: "fcn.00001340" },
        status: "changed",
        method: "mnemonics",
        lines_added: 1,
        lines_removed: 1,
        constants_added: ["0x2710"],
        constants_removed: ["0x3e8"],
        calls_added: ["fcn.00001a40"],
        calls_removed: ["fcn.00001900"],
      }),
    ]);
  });

  it("pairs identical thunks by the routines they jump to", async () => {
    const { functions } = await report({ view: "functions" });
    const partner = (address: string) =>
      functions.find((row) => row.left.address === address)?.right.address;
    expect([partner("0x1500"), partner("0x1600")]).toEqual([
      "0x1540",
      "0x1640",
    ]);
    expect(functions.find((row) => row.left.address === "0x1500")?.method).toBe(
      "call-graph",
    );
    expect(functions.find((row) => row.left.name === "main")?.method).toBe(
      "name",
    );
  });

  it("lists functions found in one build only, and pages and filters", async () => {
    const unmatched = await report({ view: "unmatched" });
    expect(unmatched.unmatched).toEqual([
      expect.objectContaining({
        status: "removed",
        address: "0x1900",
        strings: ["cheat detected"],
      }),
      expect.objectContaining({
        status: "added",
        address: "0x1a40",
        strings: ["tamper detected"],
      }),
    ]);
    expect(
      (await report({ view: "unmatched", status: "added" })).unmatched,
    ).toHaveLength(1);
    const page = await report({ view: "functions", offset: 2, limit: 3 });
    expect(page.page).toMatchObject({ total: 9, returned: 3, offset: 2 });
    expect(
      (await report({ view: "functions", status: "changed" })).functions,
    ).toHaveLength(1);
    expect(
      (await report({ view: "functions", query: "MAIN" })).functions.map(
        ({ left: { name } }) => name,
      ),
    ).toEqual(["main"]);
  });

  it("aligns one function's instructions, by either build's address or name", async () => {
    const shown = await report({ view: "function", function: "0x1340" });
    expect(shown.functions[0]?.left.address).toBe("0x1300");
    expect(shown.listing.filter(({ change }) => change !== "same")).toEqual([
      {
        change: "removed",
        left: "0x1310: imul eax, eax, 0x3e8",
        right: null,
      },
      {
        change: "added",
        left: null,
        right: "0x1350: imul eax, eax, 0x2710",
      },
    ]);
    const lone = await report({ view: "function", function: "fcn.00001a40" });
    expect(lone.unmatched[0]?.status).toBe("added");
    expect(lone.listing.every(({ change }) => change === "added")).toBe(true);
  });

  it("analyzes each build once while paging through views", () => {
    expect(sessions).toBe(2);
  });

  it("refuses relative paths, a missing function and builds from different providers", async () => {
    expect(await service.inspect({ left: "game-1.0", right })).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    expect(
      await service.inspect({
        left,
        right,
        view: "function",
        function: "nope",
      }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["function"], reason: "invalid_value" }] },
    });
    expect(
      await service.inspect({ left, right, view: "function" }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["function"], reason: "missing_argument" }] },
    });
    let first = true;
    const mixed = new BinaryDiffService(
      new BinaryDiffInspector(async () => {
        const provider = first ? "one" : "two";
        first = false;
        return ok(
          fixtureSession(
            builds,
            (path) => digests.get(path) ?? "0".repeat(64),
            provider,
          ),
        );
      }),
    );
    expect(await mixed.inspect({ left, right })).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["right"] }] },
    });
  });
});
