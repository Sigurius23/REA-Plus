import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { Minidump } from "../../domain/minidump/minidump.js";
import { ok } from "../../domain/result.js";
import { MinidumpService } from "./MinidumpService.js";

const PATH = "/crashes/game.dmp";
const report = (): Minidump => ({
  dump: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 100,
    created: null,
    flags: "0x0",
    streams: [],
  },
  system: null,
  process: { process_id: null, created: null },
  exception: null,
  selected_thread: { id: 7, registers: null, stack_scan: [] },
  threads: [],
  modules: [],
  unloaded_modules: [],
  memory: { ranges: 0, bytes: 0, full_memory: false },
  limitations: [],
});
const service = (value: Minidump) =>
  new MinidumpService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "minidump", name: "minidump", version: "1" },
            { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
          ),
        ),
      ),
  });

it.each([
  { path: "game.dmp" },
  { path: PATH, thread_id: -1 },
  { path: PATH, stack_scan_limit: 257 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new MinidumpService({
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

it.each(["path", "thread", "scan"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.dump.path = "/other.dmp";
    if (problem === "thread" && value.selected_thread !== null)
      value.selected_thread.id = 8;
    if (problem === "scan" && value.selected_thread !== null)
      value.selected_thread.stack_scan = [
        { slot: "0x1", value: "0x2", module: "m", offset: "0x0" },
        { slot: "0x9", value: "0x2", module: "m", offset: "0x0" },
      ];
    expect(
      await service(value).inspect({
        path: PATH,
        thread_id: 7,
        stack_scan_limit: 1,
      }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
  },
);

it("records the dump as observed Evidence", async () => {
  expect(await service(report()).inspect({ path: PATH })).toMatchObject({
    ok: true,
    value: { operation: "inspect_minidump", confidence: "observed" },
  });
});
