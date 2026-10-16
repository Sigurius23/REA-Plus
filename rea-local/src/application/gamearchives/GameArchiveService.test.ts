import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { GameArchive } from "../../domain/gamearchives/gameArchive.js";
import { ok } from "../../domain/result.js";
import { GameArchiveService } from "./GameArchiveService.js";

const PATH = "/games/demo/demo.pck";
const row = (path: string): GameArchive["entries"][number] => ({
  path,
  size: 4,
  offset: 64,
  stored_in: null,
  stored_size: 4,
  compression: null,
  inline_bytes: 0,
  encrypted: false,
  removed: false,
  group: null,
  checksum: null,
});
const report = (): GameArchive => ({
  archive: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 100,
    format: "godot_pck",
    version: "3",
    engine_version: "4.5.1",
    embedded_at: null,
    flags: [],
    entries: 1,
    entry_bytes: 4,
    extensions: [],
    notes: [],
  },
  page: {
    query: null,
    extension: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  entries: [row("main.gd")],
  entry: null,
  limitations: [],
});
const service = (value: GameArchive) =>
  new GameArchiveService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "archive", name: "archive", version: "1" },
            { subject: { path: PATH, format: "file", sha256: "a".repeat(64) } },
          ),
        ),
      ),
  });

it.each([
  { path: "demo.pck" },
  { path: PATH, extension: ".gd" },
  { path: PATH, limit: 1001 },
  { path: PATH, preview_bytes: 65_537 },
  { path: PATH, entry: "" },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new GameArchiveService({
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

it.each(["path", "rows", "page", "entry", "preview", "digest"])(
  "rejects a report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.archive.path = "/other.pck";
    if (problem === "rows") value.entries.push(row("other.gd"));
    if (problem === "page") value.page.offset = 3;
    if (problem === "entry")
      value.entry = {
        path: "main.gd",
        size: 4,
        available: true,
        reason: null,
        sha256: "c".repeat(64),
        checksum_verified: null,
        encoding: "utf8",
        preview: "text",
        truncated: false,
      };
    if (problem === "digest") value.archive.sha256 = "b".repeat(64);
    const input =
      problem === "preview"
        ? { path: PATH, limit: 1, entry: "main.gd", preview_bytes: 2 }
        : { path: PATH, limit: 1 };
    if (problem === "preview")
      value.entry = {
        path: "main.gd",
        size: 4,
        available: true,
        reason: null,
        sha256: "c".repeat(64),
        checksum_verified: null,
        encoding: "hex",
        preview: "0a0b0c0d",
        truncated: true,
      };
    expect(await service(value).inspect(input)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  },
);

it("records the archive as observed Evidence", async () => {
  expect(
    await service(report()).inspect({ path: PATH, limit: 1 }),
  ).toMatchObject({
    ok: true,
    value: { operation: "inspect_game_archive", confidence: "observed" },
  });
});
