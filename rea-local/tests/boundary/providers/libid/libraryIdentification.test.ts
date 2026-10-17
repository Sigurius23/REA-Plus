import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createLibraryIdentificationService } from "../../../../src/composition/libraryIdentification.js";
import type { LibraryIdentificationReport } from "../../../../src/domain/libid/libraryIdentification.js";
import {
  fixtureExecutable,
  fixtureLibrary,
} from "../../../fixtures/libraryFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createLibraryIdentificationService();
let root = "";
let binary = "";
let library = "";
let symbols = new Map<string, number>();

beforeAll(async () => {
  root = (await createTestWorkspace("rea-libid-")).root;
  binary = join(root, "game");
  library = join(root, "libgame.a");
  const executable = fixtureExecutable();
  symbols = executable.symbols;
  await writeFile(binary, executable.file);
  await writeFile(library, fixtureLibrary());
});
afterAll(async () => {
  await service.close();
  await removeTestWorkspace(root);
});

const identify = async (input: Record<string, unknown> = {}) => {
  const result = await service.inspect({
    path: binary,
    libraries: [library],
    ...input,
  });
  if (!result.ok) throw result.error;
  return result.value;
};
const report = async (input: Record<string, unknown> = {}) =>
  (await identify(input)).normalized_result as LibraryIdentificationReport;
const at = (name: string) => `0x${(symbols.get(name) ?? 0).toString(16)}`;

describe("identify_library_functions on a built library and binary", () => {
  it("reads the archive's members and counts what it identified", async () => {
    const evidence = await identify();
    expect(evidence.provider.id).toBe("library-identification");
    expect(evidence.confidence).toBe("inferred");
    const summary = evidence.normalized_result as LibraryIdentificationReport;
    expect(summary.file).toMatchObject({ format: "elf", machine: "x86-64" });
    expect(summary.libraries).toEqual([
      expect.objectContaining({
        kind: "archive",
        format: "elf",
        machine: "x86-64",
        members: 3,
        unreadable_members: 0,
        functions: 11,
        short_functions: 0,
        identified: 10,
      }),
    ]);
    expect(summary.summary).toMatchObject({
      identified: 10,
      unique: 4,
      resolved: 6,
      ambiguous: 0,
    });
    expect(summary.functions).toEqual([]);
  });

  it("names every function, settling same-byte candidates by calls, strings and layout", async () => {
    const { functions } = await report({ view: "functions" });
    const named = Object.fromEntries(
      functions.map(({ address, names, status }) => [
        address,
        `${names.join("|")} ${status}`,
      ]),
    );
    expect(named).toEqual({
      [at("adler_update")]: "adler_update unique",
      [at("crc_update")]: "crc_update unique",
      [at("adler")]: "adler resolved",
      [at("crc")]: "crc resolved",
      [at("say_hello")]: "say_hello resolved",
      [at("say_goodbye")]: "say_goodbye resolved",
      [at("anchor_routine")]: "anchor_routine unique",
      [at("tell")]: "tell resolved",
      [at("tell64")]: "tell64 resolved",
      [at("stream_close")]: "_IO_stream_close|stream_close unique",
    });
    expect(
      functions.find(({ names }) => names.includes("say_hello")),
    ).toMatchObject({
      member: "strings.o",
      library: "libgame.a",
      references: { confirmed: 1, contradicted: 0, unchecked: 1 },
    });
    expect(
      functions.find(({ names }) => names.includes("adler")),
    ).toMatchObject({ references: { confirmed: 1, contradicted: 0 } });
  });

  it("filters, pages and skips static functions on request", async () => {
    expect(
      (await report({ view: "functions", status: "unique" })).functions,
    ).toHaveLength(4);
    expect(
      (await report({ view: "functions", query: "TELL" })).functions.map(
        ({ names }) => names[0],
      ),
    ).toEqual(["tell", "tell64"]);
    const page = await report({ view: "functions", offset: 8, limit: 5 });
    expect(page.page).toMatchObject({ total: 10, returned: 2 });
    const exported = await report({ include_local: false });
    expect(exported.libraries[0]).toMatchObject({ functions: 10 });
    // The static neighbour is gone, but stream_close still places the twins.
    expect(exported.summary).toMatchObject({ identified: 9, ambiguous: 0 });
  });

  it("refuses relative paths, files it cannot read and non-executable targets", async () => {
    expect(
      await service.inspect({ path: "game", libraries: [library] }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
    expect(
      await service.inspect({
        path: binary,
        libraries: [join(root, "missing.a")],
      }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["libraries", 0] }] },
    });
    expect(
      await service.inspect({ path: library, libraries: [library] }),
    ).toMatchObject({ ok: false, error: { issues: [{ path: ["path"] }] } });
  });
});
