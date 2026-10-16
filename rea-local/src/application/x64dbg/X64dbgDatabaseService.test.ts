import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { X64dbgDatabaseReport } from "../../domain/x64dbg/x64dbgDatabase.js";
import { ok } from "../../domain/result.js";
import { X64dbgDatabaseService } from "./X64dbgDatabaseService.js";

const PATH = "/x64dbg/db/game.exe.dd64";
const DIGEST = "a".repeat(64);
const label = (module: string): X64dbgDatabaseReport["labels"][number] => ({
  module,
  address: "0x1000",
  manual: true,
  text: "LoadHealth",
  file_offset: null,
  section: null,
});
const report = (): X64dbgDatabaseReport => ({
  database: {
    path: PATH,
    sha256: DIGEST,
    bytes: 10,
    compressed: false,
    json_bytes: 10,
    hash_algorithm: null,
    debuggee_hash: null,
    sections: ["labels"],
    modules: ["game.exe"],
    notes: null,
    init_script: null,
    plugins: [],
  },
  module_file: null,
  summary: {
    labels: 1,
    comments: 0,
    bookmarks: 0,
    functions: 0,
    arguments: 0,
    loops: 0,
    breakpoints: 0,
    xrefs: 0,
    watch: 0,
    mismatched_breakpoints: null,
  },
  page: {
    view: "labels",
    module: "game.exe",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  labels: [label("game.exe")],
  comments: [],
  bookmarks: [],
  functions: [],
  arguments: [],
  loops: [],
  breakpoints: [],
  xrefs: [],
  watch: [],
  limitations: [],
});
const service = (value: X64dbgDatabaseReport) =>
  new X64dbgDatabaseService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "x64dbg", name: "x64dbg", version: "1" },
            { subject: { path: PATH, format: "file", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, module: "game.exe", limit: 1 };

it.each([
  { path: "game.exe.dd64" },
  { path: PATH, module_path: "game.exe" },
  { path: PATH, view: "patches" },
  { path: PATH, limit: 0 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new X64dbgDatabaseService({
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

it.each(["path", "view", "module", "rows", "page", "digest", "module_file"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.database.path = "/other.dd64";
    if (problem === "view") value.page.view = "comments";
    if (problem === "module") value.labels = [label("kernel32.dll")];
    if (problem === "rows") value.labels.push(label("game.exe"));
    if (problem === "page") value.page.offset = 2;
    if (problem === "digest") value.database.sha256 = "b".repeat(64);
    if (problem === "module_file")
      value.module_file = {
        path: "/game.exe",
        name: "game.exe",
        sha256: DIGEST,
        format: "pe",
        image_base: null,
      };
    expect(await service(value).inspect(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the database as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_x64dbg_database", confidence: "observed" },
  });
});
