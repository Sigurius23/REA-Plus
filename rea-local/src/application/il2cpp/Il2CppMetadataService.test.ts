import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { Il2CppMetadata } from "../../domain/il2cpp/il2cppMetadata.js";
import { ok } from "../../domain/result.js";
import { Il2CppMetadataService } from "./Il2CppMetadataService.js";

const PATH = "/games/Example_Data/il2cpp_data/Metadata/global-metadata.dat";
const report = (): Il2CppMetadata => ({
  metadata: {
    path: PATH,
    sha256: "a".repeat(64),
    bytes: 10,
    wire_version: 29,
    unity_range: "2022.1-2022.3",
  },
  native_binary: null,
  counts: { types: 1, methods: 0, fields: 0 },
  native: null,
  page: {
    view: "classes",
    query: null,
    offset: 0,
    limit: 25,
    total: 1,
    returned: 1,
  },
  classes: [
    {
      index: 0,
      name: "Game.Player",
      namespace: "Game",
      short_name: "Player",
      base: null,
      base_type_index: null,
      flags: "0x00000001",
      token: "0x02000001",
      interfaces: [],
      field_count: 0,
      method_count: 0,
      member_scope: "all",
      fields: [],
      methods: [],
    },
  ],
  string_literals: [],
  interop: [],
  assemblies: [],
  tool_profile: {
    tool: "r2unity",
    version: "1.2.8",
    verified_version: "1.2.8",
    executable_path: "/tools/r2unity",
    executable_sha256: "f".repeat(64),
    arguments: [["-c", "-j", "<metadata_path>"]],
    timeout_ms: 1,
    output_budget_bytes: 1,
    cached: false,
  },
  runtime_execution: "not-performed",
  limitations: [],
});
const service = (value: Il2CppMetadata, sha256 = value.metadata.sha256) =>
  new Il2CppMetadataService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "r2unity", name: "r2unity", version: "r2unity@1.2" },
            { subject: { path: PATH, format: "file", sha256 } },
          ),
        ),
      ),
  });

it.each([
  { metadata_path: "global-metadata.dat" },
  { metadata_path: PATH, binary_path: "GameAssembly.so" },
  { metadata_path: PATH, view: "methods" },
  { metadata_path: PATH, limit: 0 },
  { metadata_path: PATH, limit: 201 },
  { metadata_path: PATH, code_registration: "4202496" },
  { metadata_path: PATH, query: "" },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new Il2CppMetadataService({
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

it.each([
  "path",
  "digest",
  "binary",
  "view",
  "offset",
  "returned",
  "other-view",
])(
  "rejects a provider report that drifts from the request: %s",
  async (problem) => {
    const value = report();
    if (problem === "path") value.metadata.path = "/other.dat";
    if (problem === "binary")
      value.native_binary = { path: "/x.so", sha256: "b".repeat(64), bytes: 1 };
    if (problem === "view") value.page.view = "interop";
    if (problem === "offset") value.page.offset = 1;
    if (problem === "returned") value.page.returned = 0;
    if (problem === "other-view")
      value.assemblies = [
        {
          name: "A",
          version: "1.0.0.0",
          culture: "neutral",
          public_key_token: null,
          image: "A.dll",
          image_index: 0,
          token: "0x20000001",
          flags: "0x00000000",
          hash_algorithm: "0x00008004",
          references: [],
        },
      ];
    expect(
      await service(
        value,
        problem === "digest" ? "b".repeat(64) : value.metadata.sha256,
      ).inspect({ metadata_path: PATH }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
  },
);

it("records the page as derived Evidence without undefined parameters", async () => {
  const result = await service(report()).inspect({ metadata_path: PATH });
  expect(result).toMatchObject({
    ok: true,
    value: {
      operation: "inspect_il2cpp_metadata",
      confidence: "derived",
      parameters: {
        metadata_path: PATH,
        view: "classes",
        offset: 0,
        limit: 25,
      },
      normalized_result: { classes: [{ name: "Game.Player" }] },
    },
  });
  if (result.ok)
    expect(Object.keys(result.value.parameters ?? {}).sort()).toEqual([
      "limit",
      "metadata_path",
      "offset",
      "view",
    ]);
});
