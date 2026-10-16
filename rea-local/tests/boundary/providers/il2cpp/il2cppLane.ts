import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { Il2CppMetadataService } from "../../../../src/application/il2cpp/Il2CppMetadataService.js";
import type { Il2CppMetadata } from "../../../../src/domain/il2cpp/il2cppMetadata.js";
import {
  createIl2CppGameAssembly,
  createIl2CppMetadata,
  IL2CPP_FIXTURE,
} from "../../../fixtures/il2cppFixture.js";

/** Fixture files written once per lane. */
export interface Il2CppLaneFiles {
  readonly metadata: string;
  readonly binary: string;
  readonly stripped: string;
}

export const writeIl2CppFixtures = async (
  root: string,
): Promise<Il2CppLaneFiles> => {
  const files = {
    metadata: join(root, "global-metadata.dat"),
    binary: join(root, "GameAssembly.so"),
    stripped: join(root, "GameAssembly.stripped.so"),
  };
  await writeFile(files.metadata, createIl2CppMetadata());
  await writeFile(files.binary, createIl2CppGameAssembly());
  await writeFile(files.stripped, createIl2CppGameAssembly({ symbols: false }));
  return files;
};

const address = (slot: number) => `0x${IL2CPP_FIXTURE.stub(slot).toString(16)}`;

/** Inspect and return the report, failing the test on a typed error. */
export const inspectReport = async (
  service: Il2CppMetadataService,
  input: Record<string, unknown>,
): Promise<Il2CppMetadata> => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as Il2CppMetadata;
};

/** One lane: the service under test and its fixture files. */
type Lane = () => { service: Il2CppMetadataService; files: Il2CppLaneFiles };

const classListingCases = (lane: Lane): void => {
  describe("class listings", () => {
    it("lists every type from metadata alone without native addresses", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
      });
      expect(report).toMatchObject({
        metadata: {
          path: files.metadata,
          bytes: createIl2CppMetadata().length,
          wire_version: 29,
          unity_range: "2022.1-2022.3",
        },
        native_binary: null,
        native: null,
        counts: {
          types: IL2CPP_FIXTURE.types,
          methods: IL2CPP_FIXTURE.methods,
          fields: IL2CPP_FIXTURE.fields,
        },
        page: { view: "classes", total: 11, returned: 11, offset: 0 },
        string_literals: [],
        interop: [],
        assemblies: [],
        runtime_execution: "not-performed",
      });
      expect(report.classes.map(({ name }) => name)).toContain(
        "Game.Licensing.LicenseCheck",
      );
      expect(
        report.classes.flatMap(({ methods }) => methods).map((m) => m.address),
      ).toEqual(Array.from({ length: 8 }, () => null));
    });

    it("keeps only matching members when the class name does not match", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.binary,
        query: "health",
      });
      expect(report.classes).toMatchObject([
        {
          name: "Game.Player",
          interfaces: [{ type_index: 8, name: "Game.IDamageable" }],
          field_count: 2,
          method_count: 4,
          member_scope: "matching",
          fields: [{ name: "health", type: "System.Int32" }],
          methods: [{ name: "get_Health", address: address(4) }],
        },
      ]);
    });

    it("pages in metadata order and reuses the parsed listing", async () => {
      const { service, files } = lane();
      const first = await inspectReport(service, {
        metadata_path: files.metadata,
        offset: 9,
        limit: 1,
      });
      expect(first.page).toEqual({
        view: "classes",
        query: null,
        offset: 9,
        limit: 1,
        total: 11,
        returned: 1,
      });
      expect(first.classes.map(({ index }) => index)).toEqual([9]);
      const beyond = await inspectReport(service, {
        metadata_path: files.metadata,
        offset: 40,
      });
      expect(beyond.page).toMatchObject({ total: 11, returned: 0 });
      expect(beyond.tool_profile.cached).toBe(true);
    });
  });
};

const nativeAddressCases = (lane: Lane): void => {
  describe("native addresses", () => {
    it("recovers method addresses through g_CodeRegistration", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.binary,
        query: "LICENSE",
      });
      expect(report.native).toEqual({
        method_addresses_recovered: true,
        source: "symbol",
        code_registration: "0x402000",
        metadata_registration: null,
        method_pointers: "0x402100",
        code_gen_modules: "0x402100",
        tables: [],
      });
      expect(report.page).toMatchObject({ total: 1, returned: 1 });
      expect(report.classes).toEqual([
        {
          index: 9,
          name: "Game.Licensing.LicenseCheck",
          namespace: "Game.Licensing",
          short_name: "LicenseCheck",
          base: "System.Object",
          base_type_index: 0,
          flags: "0x00100181",
          token: "0x02000004",
          interfaces: [],
          field_count: 1,
          method_count: 2,
          member_scope: "all",
          fields: [
            {
              index: 0,
              name: "SecretKey",
              type: "System.String",
              type_index: 1,
              token: "0x04000001",
            },
          ],
          methods: [
            {
              index: 2,
              name: "Verify",
              full_name: "Game.Licensing.LicenseCheck.Verify(1)",
              parameter_count: 1,
              address: address(1),
              token: "0x06000003",
              flags: "0x0096",
              iflags: "0x0000",
              attributes: "public static",
            },
            {
              index: 3,
              name: "NativeHash",
              full_name: "Game.Licensing.LicenseCheck.NativeHash(1)",
              parameter_count: 1,
              address: address(2),
              token: "0x06000004",
              flags: "0x2091",
              iflags: "0x0000",
              attributes: "private static extern",
            },
          ],
        },
      ]);
    });

    it("reports a missing address for an abstract interface method", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.binary,
        query: "IDamageable",
      });
      expect(report.classes[0]?.methods).toMatchObject([
        {
          name: "TakeDamage",
          address: null,
          attributes: "public abstract virtual",
        },
      ]);
    });

    it("finds registration in a stripped binary by scan or override", async () => {
      const { service, files } = lane();
      const scanned = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.stripped,
        query: "Verify",
      });
      expect(scanned.native).toMatchObject({
        source: "heuristic",
        code_registration: null,
        code_gen_modules: "0x402100",
      });
      expect(scanned.classes[0]?.methods[0]?.address).toBe(address(1));
      const overridden = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.stripped,
        code_registration: "0x402000",
        query: "Verify",
      });
      expect(overridden.native).toMatchObject({
        source: "override",
        code_registration: "0x402000",
      });
      expect(overridden.tool_profile.arguments).toEqual([
        [
          "-c",
          "-j",
          "-f",
          "-O",
          "g_CodeRegistration=0x402000",
          "<binary_path>",
          "<metadata_path>",
        ],
      ]);
    });
  });
};

const otherViewCases = (lane: Lane): void => {
  describe("other views", () => {
    it("decodes string literals from the metadata bytes", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        view: "string_literals",
        limit: 200,
      });
      expect(report.page).toMatchObject({ total: 6, returned: 6 });
      expect(report.string_literals.map(({ text }) => text)).toEqual([
        "SECRET-KEY-42",
        "https://license.example.invalid/v1/verify",
        'Grüße, "Spieler"\n',
        "",
        "C:\\Games\\Save\t1",
        "A\uFFFD\uFFFD\uFFFD\u0001B",
      ]);
      expect(report.string_literals[5]).toMatchObject({
        bytes: 6,
        utf8_valid: false,
        hex: "41eda0800142",
      });
      expect(report.string_literals[2]).toMatchObject({
        bytes: 19,
        utf8_valid: true,
        hex: null,
      });
      const metadata = createIl2CppMetadata();
      for (const literal of report.string_literals)
        expect(
          metadata.subarray(
            literal.file_offset,
            literal.file_offset + literal.bytes,
          ),
        ).toEqual(
          literal.hex === null
            ? Buffer.from(literal.text, "utf8")
            : Buffer.from(literal.hex, "hex"),
        );
      const filtered = await inspectReport(service, {
        metadata_path: files.metadata,
        view: "string_literals",
        query: "EXAMPLE.invalid",
      });
      expect(filtered.string_literals.map(({ index }) => index)).toEqual([1]);
    });

    it("lists P/Invoke and reverse-P/Invoke methods", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        binary_path: files.binary,
        view: "interop",
      });
      expect(report.native).toBeNull();
      expect(report.interop).toEqual([
        {
          kind: "pinvoke",
          image: "Assembly-CSharp.dll",
          method: "Game.Licensing.LicenseCheck.NativeHash",
          token: "0x06000004",
          flags: "0x2091",
          iflags: "0x0000",
          attribute: null,
          dll: null,
          entry: null,
          wrapper_address: null,
          wrapper_index: null,
          confidence: 100,
        },
        {
          kind: "reverse_pinvoke",
          image: "Assembly-CSharp.dll",
          method: "Game.Player.OnNativeEvent",
          token: "0x06000007",
          flags: "0x0091",
          iflags: "0x0000",
          attribute: "MonoPInvokeCallback",
          dll: null,
          entry: null,
          wrapper_address: null,
          wrapper_index: null,
          confidence: 100,
        },
      ]);
    });

    it("lists assemblies with versions and references", async () => {
      const { service, files } = lane();
      const report = await inspectReport(service, {
        metadata_path: files.metadata,
        view: "assemblies",
      });
      expect(report.assemblies).toEqual([
        {
          name: "mscorlib",
          version: "4.0.0.0",
          culture: "neutral",
          public_key_token: "b77a5c561934e089",
          image: "mscorlib.dll",
          image_index: 0,
          token: "0x20000001",
          flags: "0x00000001",
          hash_algorithm: "0x00008004",
          references: [],
        },
        {
          name: "Assembly-CSharp",
          version: "1.2.3.4",
          culture: "neutral",
          public_key_token: null,
          image: "Assembly-CSharp.dll",
          image_index: 1,
          token: "0x20000001",
          flags: "0x00000000",
          hash_algorithm: "0x00008004",
          references: [{ name: "mscorlib", version: "4.0.0.0" }],
        },
      ]);
    });
  });
};

const admissionCases = (lane: Lane): void => {
  describe("selection admission", () => {
    it("rejects files r2unity must not see", async () => {
      const { service, files } = lane();
      const notMetadata = `${files.metadata}.txt`;
      await writeFile(notMetadata, "encrypted?");
      const cases = [
        [{ metadata_path: notMetadata }, "metadata_path"],
        [
          { metadata_path: files.metadata, binary_path: files.metadata },
          "binary_path",
        ],
        [
          { metadata_path: files.metadata, code_registration: "0x402000" },
          "code_registration",
        ],
        [{ metadata_path: "global-metadata.dat" }, "metadata_path"],
      ] as const;
      for (const [input, field] of cases)
        expect(await service.inspect(input)).toMatchObject({
          ok: false,
          error: {
            _tag: "AnalysisInputError",
            issues: [{ path: [field] }],
          },
        });
    });
  });
};

/**
 * Expectations every r2unity lane must meet on the fixture pair; the fake
 * lane replays recorded 1.2.8 output and the real lane runs r2unity itself.
 */
export const describeIl2CppViews = (lane: Lane): void => {
  classListingCases(lane);
  nativeAddressCases(lane);
  otherViewCases(lane);
  admissionCases(lane);
};
