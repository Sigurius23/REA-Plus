import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { RenpyScriptReport } from "../../domain/renpy/renpyScript.js";
import { ok } from "../../domain/result.js";
import { RenpyScriptService } from "./RenpyScriptService.js";

const PATH = "/games/vn/game/script.rpyc";
const say = (label: string): RenpyScriptReport["dialogue"][number] => ({
  label,
  file: "game/script.rpy",
  line: 6,
  who: "e",
  what: "Hello.",
  identifier: `${label}_1a2b3c4d`,
  language: null,
});
const report = (): RenpyScriptReport => ({
  script: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 100,
    format: "rpyc2",
    slot: 2,
    script_version: 5003000,
    source_files: ["game/script.rpy"],
    statements: 1,
    statement_kinds: [{ kind: "TranslateSay", count: 1 }],
  },
  summary: {
    labels: 1,
    dialogue: 1,
    menus: 0,
    definitions: 0,
    translations: 0,
    languages: [],
    speakers: [{ who: "e", lines: 1 }],
  },
  page: {
    view: "dialogue",
    label: "start",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  labels: [],
  dialogue: [say("start")],
  menus: [],
  definitions: [],
  translations: [],
  limitations: [],
});
const service = (value: RenpyScriptReport) =>
  new RenpyScriptService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "renpy", name: "renpy", version: "1" },
            { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, view: "dialogue", label: "start", limit: 1 };

it.each([
  { path: "script.rpyc" },
  { path: PATH, view: "screens" },
  { path: PATH, limit: 0 },
  { path: PATH, label: "" },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new RenpyScriptService({
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

it.each(["path", "view", "label", "rows", "page", "digest"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.script.path = "/other.rpyc";
    if (problem === "view") value.page.view = "labels";
    if (problem === "label") value.dialogue = [say("other")];
    if (problem === "rows") value.dialogue.push(say("start"));
    if (problem === "page") value.page.offset = 2;
    if (problem === "digest") value.script.sha256 = "b".repeat(64);
    expect(await service(value).inspect(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the script as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_renpy_script", confidence: "observed" },
  });
});
