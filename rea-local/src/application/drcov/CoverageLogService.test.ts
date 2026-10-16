import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { CoverageLog } from "../../domain/drcov/coverageLog.js";
import { ok } from "../../domain/result.js";
import { CoverageLogService } from "./CoverageLogService.js";

const PATH = "/traces/drcov.game.log";
const identity = (path: string) => ({
  path,
  sha256: "a".repeat(64),
  bytes: 10,
  drcov_version: 3,
  flavor: "drcov-64",
  module_table_version: 5,
  block_table: "binary" as const,
  block_entries: 1,
});
const report = (): CoverageLog => ({
  log: identity(PATH),
  baseline: null,
  modules: [],
  selected_module: { path: "/games/GameAssembly.so", segments: [] },
  page: { offset: 0, limit: 500, total: 1, returned: 1 },
  blocks: [
    {
      image_offset: "0x10",
      static_address: "0x10",
      runtime_address: "0x7f0000000010",
      size: 4,
      segment_id: 0,
    },
  ],
  limitations: [],
});
const service = (value: CoverageLog) =>
  new CoverageLogService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "drcov", name: "drcov", version: "1" },
            {
              subject: {
                path: PATH,
                format: "file",
                sha256: value.log.sha256,
              },
            },
          ),
        ),
      ),
  });

it.each([
  { path: "drcov.log" },
  { path: PATH, baseline_path: "idle.log" },
  { path: PATH, limit: 5001 },
  { path: PATH, module: "" },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new CoverageLogService({
    close: () => Promise.resolve(),
    inspect: () => {
      throw new Error("Must not execute");
    },
  });
  expect(await unused.inspect(input)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it.each(["path", "baseline", "module", "returned"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.log.path = "/other.log";
    if (problem === "baseline") value.baseline = identity("/idle.log");
    if (problem === "module") value.selected_module = null;
    if (problem === "returned") value.page.returned = 0;
    expect(
      await service(value).inspect({ path: PATH, module: "GameAssembly.so" }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
  },
);

it("records the page as observed Evidence", async () => {
  expect(
    await service(report()).inspect({ path: PATH, module: "GameAssembly.so" }),
  ).toMatchObject({
    ok: true,
    value: {
      operation: "inspect_coverage_log",
      confidence: "observed",
      normalized_result: { blocks: [{ static_address: "0x10" }] },
    },
  });
});
