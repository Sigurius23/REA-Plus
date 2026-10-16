import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { GameMakerDataReport } from "../../domain/gamemaker/gameMakerData.js";
import { ok } from "../../domain/result.js";
import { GameMakerDataService } from "./GameMakerDataService.js";

const PATH = "/games/gm/data.win";
const DIGEST = "a".repeat(64);
const sprite = (
  kind: "sprite" | "object" = "sprite",
): GameMakerDataReport["resources"][number] => ({
  kind,
  index: 0,
  name: "spr_player",
  offset: 100,
  fields: {},
});
const report = (): GameMakerDataReport => ({
  file: {
    path: PATH,
    sha256: DIGEST,
    bytes: 100,
    form_offset: 0,
    form_size: 92,
  },
  general: null,
  summary: {
    chunks: 1,
    resources: [{ kind: "sprite", count: 1 }],
    code: 0,
    strings: 0,
    functions: 0,
    variables: 0,
    textures: 0,
    audio: 0,
  },
  page: {
    view: "resources",
    kind: "sprite",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  chunks: [],
  resources: [sprite()],
  code: [],
  strings: [],
  symbols: [],
  textures: [],
  audio: [],
  limitations: [],
});
const service = (value: GameMakerDataReport) =>
  new GameMakerDataService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "gamemaker", name: "gamemaker", version: "1" },
            { subject: { path: PATH, format: "file", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, view: "resources", kind: "sprite", limit: 1 };

it.each([
  { path: "data.win" },
  { path: PATH, view: "objects" },
  { path: PATH, kind: "monster" },
  { path: PATH, limit: 0 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new GameMakerDataService({
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

it.each(["path", "view", "kind", "rows", "page", "digest"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.file.path = "/other.win";
    if (problem === "view") value.page.view = "code";
    if (problem === "kind") value.resources = [sprite("object")];
    if (problem === "rows") value.resources.push(sprite());
    if (problem === "page") value.page.offset = 2;
    if (problem === "digest") value.file.sha256 = "b".repeat(64);
    expect(await service(value).inspect(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the data file as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_gamemaker_data", confidence: "observed" },
  });
});
