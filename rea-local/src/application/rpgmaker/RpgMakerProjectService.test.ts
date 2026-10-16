import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { RpgMakerProjectReport } from "../../domain/rpgmaker/rpgMakerProject.js";
import { ok } from "../../domain/result.js";
import { RpgMakerProjectService } from "./RpgMakerProjectService.js";

const PATH = "/games/rpg";
const DIGEST = "a".repeat(64);
const line = (map: number): RpgMakerProjectReport["dialogue"][number] => ({
  source: "map",
  source_id: map,
  source_name: "Village",
  event_id: 1,
  event_name: "Elder",
  page: 1,
  index: 0,
  kind: "message",
  speaker: null,
  face: null,
  lines: ["Hello."],
});
const report = (): RpgMakerProjectReport => ({
  project: {
    path: PATH,
    engine: "mz",
    layout: "root",
    core_version: "1.8.0",
    data_sha256: DIGEST,
    data_files: 1,
    data_bytes: 10,
    title: "Quest",
    locale: null,
    version_id: null,
    start: null,
  },
  encryption: {
    images: false,
    audio: false,
    key: null,
    empty_passphrase: false,
    recovered_key: null,
    key_matches: null,
  },
  summary: {
    maps: 1,
    events: 1,
    common_events: 0,
    troops: 0,
    messages: 1,
    choices: 0,
    switches: 0,
    variables: 0,
    database: [],
    plugins: { total: 0, enabled: 0, missing: 0 },
    assets: { encrypted: 0, plain: 0, undecryptable: 0 },
    saves: 0,
  },
  page: {
    view: "dialogue",
    map: 1,
    table: null,
    asset: null,
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  maps: [],
  dialogue: [line(1)],
  switches: [],
  database: [],
  plugins: [],
  assets: [],
  saves: [],
  limitations: [],
});
const service = (value: RpgMakerProjectReport) =>
  new RpgMakerProjectService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "rpgmaker", name: "rpgmaker", version: "1" },
            { subject: { path: PATH, format: "directory", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, view: "dialogue", map: 1, limit: 1 };

it.each([
  { path: "games/rpg" },
  { path: PATH, view: "events" },
  { path: PATH, limit: 0 },
  { path: PATH, map: 0 },
  { path: PATH, table: "monsters" },
  { path: PATH, view: "assets", asset: "../secret.png" },
  { path: PATH, view: "assets", asset: "/etc/passwd" },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new RpgMakerProjectService({
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

it.each(["path", "view", "map", "rows", "page", "digest", "asset"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.project.path = "/other";
    if (problem === "view") value.page.view = "maps";
    if (problem === "map") value.dialogue = [line(2)];
    if (problem === "rows") value.dialogue.push(line(1));
    if (problem === "page") value.page.offset = 2;
    if (problem === "digest") value.project.data_sha256 = "b".repeat(64);
    if (problem === "asset") value.page.asset = "img/x.png";
    expect(await service(value).inspect(INPUT)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the project as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_rpgmaker_project", confidence: "observed" },
  });
});
