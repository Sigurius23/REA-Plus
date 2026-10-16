import { describe, expect, it } from "vitest";

import type { Il2CppClass } from "../domain/il2cpp/il2cppMetadata.js";
import { pageClasses, pageEntries } from "./Il2CppMetadataPage.js";
import {
  parseR2UnityAssemblies,
  parseR2UnityClasses,
  parseR2UnityInterop,
  parseR2UnityStringLiterals,
  R2UnityOutputDrift,
  unescapeR2UnityLiteral,
} from "./R2UnityOutput.js";
import { isSupportedR2UnityVersion } from "./R2UnityRelease.js";

const classesOutput = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    ok: true,
    version: 31,
    unity_range: "2023.x-6000.x",
    has_ptrs: true,
    native_source: "symbol",
    code_registration: 0x1000,
    metadata_registration: 0,
    method_pointers: 0x2000,
    code_gen_modules: 0x2000,
    native_tables: { invokerPointers: { count: 3, va: 0x3000 } },
    types: 1,
    methods: 2,
    fields: 0,
    classes: [
      {
        index: 0,
        name: "Ns.Type",
        namespace: "Ns",
        short_name: "Type",
        base: null,
        base_type_index: -1,
        flags: "0x00000001",
        token: "0x02000001",
        interfaces: [],
        fields: [],
        methods: [
          {
            index: 0,
            name: "Run",
            full_name: "Ns.Type.Run(0)",
            parameter_count: 0,
            addr: 0x10_0000_1000,
            token: "0x06000001",
            flags: "0x0006",
            iflags: "0x0000",
            attrs: "public",
          },
          {
            index: 1,
            name: "Abstract",
            full_name: "Ns.Type.Abstract(0)",
            parameter_count: 0,
            addr: 0,
            token: "0x06000002",
            flags: "0x0446",
            iflags: "0x0000",
            attrs: null,
          },
        ],
      },
    ],
    ...overrides,
  });

describe("r2unity class listings", () => {
  it("normalizes addresses, base indices and recovered tables", () => {
    const inventory = parseR2UnityClasses(classesOutput());
    expect(inventory.native).toEqual({
      method_addresses_recovered: true,
      source: "symbol",
      code_registration: "0x1000",
      metadata_registration: null,
      method_pointers: "0x2000",
      code_gen_modules: "0x2000",
      tables: [{ name: "invokerPointers", address: "0x3000", count: 3 }],
    });
    expect(inventory.classes[0]).toMatchObject({
      base_type_index: null,
      member_scope: "all",
      methods: [
        { address: "0x1000001000", attributes: "public" },
        { address: null, attributes: null },
      ],
    });
  });

  it("drops addresses when r2unity recovered no pointer table", () => {
    const inventory = parseR2UnityClasses(classesOutput({ has_ptrs: false }));
    expect(inventory.classes[0]?.methods.map(({ address }) => address)).toEqual(
      [null, null],
    );
  });

  it.each([
    ["unknown fields", { extra: true }],
    ["unsafe integers", { code_registration: 2 ** 64 }],
    ["a different native source", { native_source: "guess" }],
  ])("rejects %s", (_name, overrides) => {
    expect(() => parseR2UnityClasses(classesOutput(overrides))).toThrow(
      R2UnityOutputDrift,
    );
  });

  it("rejects non-JSON output", () => {
    expect(() => parseR2UnityClasses("ERROR: bad")).toThrow(
      /did not print JSON/u,
    );
  });
});

describe("r2unity string literals", () => {
  it("undoes every escape r2unity emits", () => {
    expect(unescapeR2UnityLiteral('a\\\\b\\"c\\n\\r\\t\\x00\\xff€')).toEqual(
      Buffer.concat([
        Buffer.from('a\\b"c\n\r\t'),
        Buffer.from([0x00, 0xff]),
        Buffer.from("€"),
      ]),
    );
    expect(() => unescapeR2UnityLiteral("\\q")).toThrow(/unknown escape/u);
    expect(() => unescapeR2UnityLiteral('a"b')).toThrow(/unescaped quote/u);
    expect(() => unescapeR2UnityLiteral("\\x4")).toThrow(/unknown escape/u);
  });

  const metadata = Buffer.concat([
    Buffer.alloc(16),
    Buffer.from("key"),
    Buffer.from([0xc3]),
  ]);

  it("cross-checks each rendering against the metadata bytes", () => {
    expect(
      parseR2UnityStringLiterals(
        '0\t0x10\t3\t"key"\n1\t0x13\t1\t"\\xc3"\n',
        metadata,
      ),
    ).toEqual([
      {
        index: 0,
        file_offset: 16,
        bytes: 3,
        text: "key",
        utf8_valid: true,
        hex: null,
      },
      {
        index: 1,
        file_offset: 19,
        bytes: 1,
        text: "\uFFFD",
        utf8_valid: false,
        hex: "c3",
      },
    ]);
    expect(parseR2UnityStringLiterals("", metadata)).toEqual([]);
  });

  it.each([
    ["a disagreeing rendering", '0\t0x10\t3\t"kez"\n', /disagrees/u],
    ["an out-of-file range", '0\t0x12\t3\t"y"\n', /outside/u],
    ["an invalid entry", "0\t0x10\t3\t<invalid>\n", /outside/u],
    ["a skipped index", '1\t0x10\t3\t"key"\n', /not an indexed literal/u],
    ["a truncated line", '0\t0x10\t3\t"key"', /mid-line/u],
  ])("rejects %s", (_name, stdout, message) => {
    expect(() => parseR2UnityStringLiterals(stdout, metadata)).toThrow(message);
  });
});

describe("r2unity interop and assemblies", () => {
  const pinvokes = (entries: unknown[] = []) =>
    JSON.stringify({
      ok: true,
      version: 29,
      pinvokes: entries,
      reverse_pinvokes: [],
      anonymous_reverse_pinvokes: [],
      interop_data: null,
    });

  it("keeps reverse wrapper addresses and rejects version disagreement", () => {
    const reverse = JSON.stringify({
      ok: true,
      version: 29,
      reverse_pinvokes: [
        {
          image: "A.dll",
          method: "A.B.C",
          token: "0x06000001",
          flags: "0x0091",
          iflags: "0x0000",
          attribute: "UnmanagedCallersOnly",
          confidence: 90,
          wrapper_va: "0x4010",
          wrapper_index: 2,
        },
      ],
    });
    expect(parseR2UnityInterop(pinvokes(), reverse).entries).toEqual([
      expect.objectContaining({
        kind: "reverse_pinvoke",
        attribute: "UnmanagedCallersOnly",
        wrapper_address: "0x4010",
        wrapper_index: 2,
      }),
    ]);
    expect(() =>
      parseR2UnityInterop(
        pinvokes(),
        JSON.stringify({ ok: true, version: 31, reverse_pinvokes: [] }),
      ),
    ).toThrow(/different metadata wire versions/u);
  });

  const sbom = (dependsOn: string[]) =>
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: {
        tools: { components: [{ type: "application", name: "r2unity" }] },
        component: {
          type: "application",
          name: "unity-build",
          version: "2022.1-2022.3",
          properties: [{ name: "unity.metadata.wire_version", value: "29" }],
        },
      },
      components: [
        {
          "bom-ref": "asm:A:1.0.0.0",
          type: "library",
          name: "A",
          version: "1.0.0.0",
          purl: "pkg:generic/unity/A@1%2e0%2e0%2e0",
          properties: [
            { name: "dotnet.culture", value: "neutral" },
            { name: "dotnet.public_key_token", value: "" },
            { name: "dotnet.hash_alg", value: "0x00008004" },
            { name: "dotnet.flags", value: "0x00000000" },
            { name: "il2cpp.image", value: "A.dll" },
            { name: "il2cpp.image_index", value: "0" },
            { name: "il2cpp.token", value: "0x20000001" },
          ],
        },
      ],
      dependencies: [{ ref: "asm:A:1.0.0.0", dependsOn }],
    });

  it("resolves assembly references by bom-ref", () => {
    expect(parseR2UnityAssemblies(sbom(["asm:A:1.0.0.0"]))).toEqual({
      wireVersion: 29,
      entries: [
        expect.objectContaining({
          name: "A",
          public_key_token: null,
          references: [{ name: "A", version: "1.0.0.0" }],
        }),
      ],
    });
    expect(() => parseR2UnityAssemblies(sbom(["asm:Missing:1"]))).toThrow(
      /does not name exactly one component/u,
    );
  });
});

describe("IL2CPP paging", () => {
  const type = (name: string, members: string[]): Il2CppClass => ({
    index: 0,
    name,
    namespace: null,
    short_name: name,
    base: null,
    base_type_index: null,
    flags: "0x00000000",
    token: "0x02000001",
    interfaces: [],
    field_count: 0,
    method_count: members.length,
    member_scope: "all",
    fields: [],
    methods: members.map((member, index) => ({
      index,
      name: member,
      full_name: null,
      parameter_count: 0,
      address: null,
      token: "0x06000001",
      flags: "0x0006",
      iflags: "0x0000",
      attributes: null,
    })),
  });

  it("matches classes by name or narrows them to matching members", () => {
    const classes = [
      type("PlayerController", ["Update", "Jump"]),
      type("Inventory", ["AddPlayerItem", "Remove"]),
      type("Audio", ["Play"]),
    ];
    const page = pageClasses(classes, "player", 0, 10);
    expect(page.total).toBe(2);
    expect(page.entries.map(({ member_scope }) => member_scope)).toEqual([
      "all",
      "matching",
    ]);
    expect(page.entries[1]?.methods.map(({ name }) => name)).toEqual([
      "AddPlayerItem",
    ]);
    expect(pageClasses(classes, undefined, 1, 1).entries).toEqual([classes[1]]);
  });

  it("counts every match while slicing one page", () => {
    expect(
      pageEntries(["ab", "Ab", "c", "AB"], {
        query: "AB",
        fields: (item) => [item],
        offset: 1,
        limit: 1,
      }),
    ).toEqual({ total: 3, entries: ["Ab"] });
  });
});

it("admits r2unity 1.2.8 and later 1.2 releases only", () => {
  expect(["1.2.8", "1.2.10"].map(isSupportedR2UnityVersion)).toEqual([
    true,
    true,
  ]);
  expect(
    ["1.2.7", "1.3.0", "2.0.0", "1.2"].map(isSupportedR2UnityVersion),
  ).toEqual([false, false, false, false]);
});
