import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { LogicCapture } from "../../domain/logic/logicCapture.js";
import { ok } from "../../domain/result.js";
import { LogicCaptureService } from "./LogicCaptureService.js";

const PATH = "/captures/board.sr";
const report = (): LogicCapture => ({
  capture: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 10,
    sigrok_version: "0.5.2",
    samplerate_hz: 1e6,
    samples: 0,
    duration_s: 0,
    unitsize: 1,
  },
  channels: [],
  analog: [],
  decode: {
    stack: ["uart:rx=D0"],
    classes: [],
    annotations: [],
    totals: [{ class: "rx-data", total: 0, returned: 0 }],
    byte_streams: [],
    tool_profile: {
      tool: "sigrok-cli",
      version: "0.7.2",
      libsigrokdecode: null,
      executable_path: "/usr/bin/sigrok-cli",
      executable_sha256: "b".repeat(64),
      arguments: [],
      timeout_ms: 1,
    },
  },
  limitations: [],
});
const service = (value: LogicCapture) =>
  new LogicCaptureService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "sigrok", name: "sigrok", version: "1" },
            { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
          ),
        ),
      ),
  });
const DECODE = {
  path: PATH,
  decoders: [{ id: "uart", channels: { rx: "D0" } }],
  annotations: ["rx-data"],
};

it.each([
  { path: "board.sr" },
  { path: PATH, decoders: [] },
  { path: PATH, decoders: [{ id: "UART;rm", channels: { rx: "D0" } }] },
  { path: PATH, decoders: [{ id: "uart", options: { baudrate: "1:2" } }] },
  { path: PATH, annotation_limit: 20_001 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new LogicCaptureService({
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

it.each(["path", "classes", "count", "no-decode"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.capture.path = "/other.sr";
    if (problem === "classes" && value.decode !== null)
      value.decode.totals = [{ class: "tx-data", total: 0, returned: 0 }];
    if (problem === "count" && value.decode !== null)
      value.decode.totals = [{ class: "rx-data", total: 1, returned: 1 }];
    if (problem === "no-decode") value.decode = null;
    expect(await service(value).inspect(DECODE)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the capture as observed Evidence", async () => {
  expect(await service(report()).inspect(DECODE)).toMatchObject({
    ok: true,
    value: { operation: "inspect_logic_capture", confidence: "observed" },
  });
});
