import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { UnityAssets } from "../../domain/unity/unityAssets.js";
import { ok } from "../../domain/result.js";
import { UnityAssetsService } from "./UnityAssetsService.js";

const PATH = "/game/Game_Data/level1";
const object = (pathId: string): UnityAssets["objects"][number] => ({
  file: "level1",
  path_id: pathId,
  class_id: 1,
  class_name: "GameObject",
  byte_start: 0,
  byte_size: 8,
  name: "Player",
  game_object: null,
  script: null,
});
const report = (): UnityAssets => ({
  file: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 100,
    format: "serialized_file",
  },
  bundle: null,
  serialized_files: [],
  classes: [],
  dependencies: [],
  page: {
    view: "objects",
    class_name: null,
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  objects: [object("1")],
  container: [],
  scripts: [],
  limitations: [],
});
const service = (value: UnityAssets) =>
  new UnityAssetsService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "unity", name: "unity", version: "1" },
            { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
          ),
        ),
      ),
  });

it.each([
  { path: "level1" },
  { path: PATH, view: "textures" },
  { path: PATH, class_name: "Texture 2D" },
  { path: PATH, limit: 1001 },
  { path: PATH, offset: -1 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new UnityAssetsService({
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

it.each(["path", "view", "rows", "page", "digest"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.file.path = "/other";
    if (problem === "view") value.page.view = "scripts";
    if (problem === "rows") value.objects.push(object("2"));
    if (problem === "page") value.page.offset = 5;
    if (problem === "digest") value.file.sha256 = "b".repeat(64);
    expect(
      await service(value).inspect({ path: PATH, limit: 1 }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
  },
);

it("records the file as observed Evidence", async () => {
  expect(
    await service(report()).inspect({ path: PATH, limit: 1 }),
  ).toMatchObject({
    ok: true,
    value: { operation: "inspect_unity_assets", confidence: "observed" },
  });
});
