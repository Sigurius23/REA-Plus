import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { EnhancedTools } from "../../../../src/application/EnhancedTools.js";
import { AnalysisProviderRegistry } from "../../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../../src/application/binary/BinarySessionComposition.js";
import { parseConfig } from "../../../../src/config/parseConfig.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import { Radare2Provider } from "../../../../src/radare2/Radare2Provider.js";
import {
  createRadare2Elf,
  RADARE2_ELF_LAYOUT as LAYOUT,
  RADARE2_ELF_SECRET,
} from "../../../fixtures/radare2Elf.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const configured = (name: string) => {
  const value = process.env[name];
  return value === undefined || value.length === 0 ? undefined : value;
};
const hex = (value: number) => `0x${value.toString(16)}`;

/**
 * One lane per engine. Both run the same provider; Rizin's analysis names
 * check_key `main` (the first call of the entry point) and prints memory
 * operand sizes, and Rizin has no pdc pseudo-code.
 */
const LANES = [
  {
    engine: "radare2",
    path: configured("REA_VERIFY_RADARE2_PATH"),
    lane: "real radare2 provider (set REA_VERIFY_RADARE2_PATH to radare2 6.x)",
    checkKeyName: "sym.check_key",
    signature: "sym.check_key (int64_t arg1);",
    lea: "lea rsi, obj.secret",
    helperListing: /lea eax, \[rdi \+ rdi\*2 \+ 1\]/u,
  },
  {
    engine: "rizin",
    path: configured("REA_VERIFY_RIZIN_PATH"),
    lane: "real Rizin dialect (set REA_VERIFY_RIZIN_PATH to Rizin 0.9.x)",
    checkKeyName: "main",
    signature: "int main(int argc, char **argv, char **envp);",
    lea: "lea rsi, qword obj.secret",
    helperListing: /lea +eax, qword \[rdi\+rdi\*2\+0x01\]/u,
  },
] as const;

const openFixture = async (executable: string | undefined) => {
  if (executable === undefined) throw new Error("engine path unset");
  const { root } = await createTestWorkspace("rea-radare2-real-");
  const runtime = join(root, "runtime");
  await writeFile(join(root, "fixture.elf"), createRadare2Elf());
  await mkdir(runtime);
  const config = parseConfig({
    REA_ANALYSIS_PROVIDER: "radare2",
    REA_RADARE2_PATH: executable,
  });
  if (!config.ok) throw config.error;
  const provider = new Radare2Provider(config.value, process.env, {
    runtimeParent: runtime,
  });
  const session = composeBinarySession(
    new AnalysisProviderRegistry([provider], "radare2"),
  );
  const opened = await session.open(join(root, "fixture.elf"));
  if (!opened.ok) throw opened.error;
  const run = async (
    operation: Parameters<typeof session.execute>[0],
    input: Readonly<Record<string, JsonValue>> = {},
  ) => {
    const result = await session.execute(operation, input);
    if (!result.ok) throw result.error;
    return result.value;
  };
  const enhanced = async (
    operation: Parameters<EnhancedTools["execute"]>[0],
    input: Readonly<Record<string, JsonValue>>,
  ) => {
    const result = await new EnhancedTools(session).execute(operation, input);
    if (!result.ok) throw result.error;
    return result.value;
  };
  return { root, runtime, session, run, enhanced };
};

/** One analyzed session per suite; closing it must remove the private copy. */
const useFixture = (executable: string | undefined) => {
  let fixture: Awaited<ReturnType<typeof openFixture>> | undefined;
  beforeAll(async () => {
    fixture = await openFixture(executable);
  });
  afterAll(async () => {
    if (fixture === undefined) return;
    try {
      expect((await fixture.session.close()).ok).toBe(true);
      await expect(readdir(fixture.runtime)).resolves.toEqual([]);
    } finally {
      await removeTestWorkspace(fixture.root);
    }
  });
  return () => {
    if (fixture === undefined) throw new Error("fixture did not open");
    return fixture;
  };
};

/** The fixture's check_key references, the same under either engine. */
const dossierReferences = (checkKey: { address: string; name: string }) => ({
  incoming_references: [
    {
      source_address: hex(LAYOUT.startCall),
      target_address: checkKey.address,
      source_procedure: { address: hex(LAYOUT.start) },
      target_procedure: checkKey,
      kind: { available: false },
    },
  ],
  referenced_strings: [
    {
      address: hex(LAYOUT.secret),
      value: RADARE2_ELF_SECRET,
      source_address: hex(LAYOUT.checkKeyLea),
    },
  ],
  referenced_names: [
    {
      address: hex(LAYOUT.secret),
      value: "secret",
      source_address: hex(LAYOUT.checkKeyLea),
    },
    {
      address: hex(LAYOUT.helper),
      value: "sym.helper",
      source_address: hex(LAYOUT.checkKeyCall),
    },
  ],
});

for (const lane of LANES) {
  const checkKey = { address: hex(LAYOUT.checkKey), name: lane.checkKeyName };

  describe.skipIf(lane.path === undefined)(`${lane.lane}: inventories`, () => {
    const fixture = useFixture(lane.path);

    it("lists procedures with engine names and the committed profile", async () => {
      const procedures = await fixture().run("list_procedures");
      expect(procedures.provider.id).toBe("radare2");
      expect(procedures.analysisProfile?.provider.id).toBe("radare2");
      expect(procedures.analysisProfile?.parameters).toMatchObject({
        engine: lane.engine,
      });
      expect(procedures.rawResult).toMatchObject({
        engine: lane.engine,
        analysis_level: "aaa",
        commands: ["aflj"],
      });
      expect(procedures.result).toEqual([
        { address: hex(LAYOUT.start), value: "entry0" },
        { address: checkKey.address, value: checkKey.name },
        { address: hex(LAYOUT.helper), value: "sym.helper" },
      ]);
    });

    it("finds strings, their references and symbol names", async () => {
      const { run } = fixture();
      const secret = { address: hex(LAYOUT.secret), value: RADARE2_ELF_SECRET };
      expect((await run("list_strings")).result).toEqual([secret]);
      expect(
        (await run("search_strings", { pattern: "secret-key" })).result,
      ).toEqual([secret]);
      expect(
        (await run("xrefs", { address: hex(LAYOUT.secret) })).result,
      ).toEqual([hex(LAYOUT.checkKeyLea)]);
      expect(
        (await run("address_name", { address: hex(LAYOUT.secret) })).result,
      ).toBe("secret");
    });

    it("reports sections with exclusive ends and permissions", async () => {
      expect((await fixture().run("list_segments")).result).toEqual([
        expect.objectContaining({
          name: ".text",
          start: hex(LAYOUT.textStart),
          end: hex(LAYOUT.textEnd),
          executable: true,
          writable: false,
          provenance: "radare2-section",
        }),
        expect.objectContaining({ name: ".rodata", executable: false }),
        expect.objectContaining({
          name: ".bss",
          start: hex(LAYOUT.bss),
          writable: true,
        }),
      ]);
    });

    it("reads only file-backed bytes and maps them to file offsets", async () => {
      const { run } = fixture();
      const helper = hex(LAYOUT.helper);
      expect(
        (await run("read_bytes", { address: helper, length: 5 })).result,
      ).toEqual({
        address: helper,
        requested_bytes: 5,
        returned_bytes: 5,
        bytes_hex: LAYOUT.helperBytes,
        complete: true,
      });
      // .bss is zero-filled by radare2, not bytes of the admitted file.
      expect(
        (await run("read_bytes", { address: hex(LAYOUT.bss), length: 4 }))
          .result,
      ).toMatchObject({ returned_bytes: 0, bytes_hex: "", complete: false });
      expect(
        (await run("address_to_file_offset", { address: helper })).result,
      ).toMatchObject({
        file_offset: LAYOUT.helperOffset,
        image_base_file_offset: 0,
      });
    });
  });

  describe.skipIf(lane.path === undefined)(`${lane.lane}: functions`, () => {
    const fixture = useFixture(lane.path);

    it("resolves symbol names and reports call edges", async () => {
      const { run } = fixture();
      expect(
        (await run("procedure_address", { procedure: "_start" })).result,
      ).toBe(hex(LAYOUT.start));
      expect(
        (await run("procedure_callers", { procedure: "helper" })).result,
      ).toEqual([hex(LAYOUT.checkKey)]);
      expect(
        (await run("procedure_callees", { procedure: "sym.check_key" })).result,
      ).toEqual([hex(LAYOUT.helper)]);
      expect(
        (await run("procedure_callees", { procedure: "entry0" })).result,
      ).toEqual([hex(LAYOUT.checkKey)]);
    });

    it("describes bodies and containing procedures", async () => {
      const { run } = fixture();
      expect(
        (await run("procedure_info", { procedure: "check_key" })).result,
      ).toMatchObject({
        name: checkKey.name,
        entrypoint: checkKey.address,
        basicblock_count: 1,
        length: 13,
        locals: [],
        classification: null,
        body: {
          available: true,
          provenance: "radare2-afbj",
          ranges: [{ start: checkKey.address, end: hex(LAYOUT.helper - 1) }],
          total_bytes: 13,
          span_bytes: 13,
          non_contiguous: false,
          contains_entry: true,
        },
      });
      expect(
        (
          await run("resolve_containing_procedure", {
            address: hex(LAYOUT.checkKeyCall),
          })
        ).result,
      ).toMatchObject({ found: true, procedure: checkKey });
      expect(
        (await run("resolve_containing_procedure", { address: "0x10" })).result,
      ).toMatchObject({ found: false, reason: "outside_segments" });
    });

    it("returns assembly, and pdc pseudo-code where the engine has it", async () => {
      const { run, session } = fixture();
      expect(
        String(
          (await run("procedure_assembly", { procedure: "helper" })).result,
        ),
      ).toMatch(lane.helperListing);
      if (lane.engine === "radare2")
        expect(
          String(
            (await run("procedure_pseudo_code", { procedure: "check_key" }))
              .result,
          ),
        ).toContain("sym.helper");
      else
        expect(
          await session.execute("procedure_pseudo_code", {
            procedure: "check_key",
          }),
        ).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisCapabilityUnavailableError" },
        });
    });

    it("drives call-graph and overview workflows", async () => {
      const { enhanced } = fixture();
      expect(
        await enhanced("get_call_graph", {
          address: "entry0",
          direction: "forward",
        }),
      ).toEqual({
        "0": [
          {
            address: hex(LAYOUT.start),
            status: "ok",
            calls: [checkKey.address],
          },
        ],
        "1": [
          {
            address: checkKey.address,
            status: "ok",
            calls: [hex(LAYOUT.helper)],
          },
        ],
        "2": [{ address: hex(LAYOUT.helper), status: "ok", calls: [] }],
      });
      expect(await enhanced("binary_overview", {})).toMatchObject({
        document: "fixture.elf",
        procedure_count: 3,
        string_count: 1,
      });
    });

    it("builds a function dossier that passes the strict dossier parser", async () => {
      expect(
        await fixture().enhanced("analyze_function", {
          procedure: "check_key",
        }),
      ).toMatchObject({
        procedure: { ...checkKey, signature: lane.signature },
        assembly: [
          `${hex(LAYOUT.checkKeyLea)}: ${lane.lea}`,
          `${hex(LAYOUT.checkKeyCall)}: call sym.helper`,
          `${hex(LAYOUT.helper - 1)}: ret`,
        ],
        callers: [{ address: hex(LAYOUT.start), name: "entry0" }],
        callees: [{ address: hex(LAYOUT.helper), name: "sym.helper" }],
        ...dossierReferences(checkKey),
        basic_blocks: [
          { start: checkKey.address, end: hex(LAYOUT.helper), successors: [] },
        ],
        unresolved_calls: [],
        native_api: null,
        ...(lane.engine === "rizin" ? { pseudocode: "" } : {}),
      });
    });
  });

  describe.skipIf(lane.path === undefined)(`${lane.lane}: caller input`, () => {
    const fixture = useFixture(lane.path);

    it("rejects unresolvable procedures, malformed addresses and other documents", async () => {
      const { session, run } = fixture();
      await run("list_procedures");
      expect(
        await session.execute("procedure_assembly", {
          procedure: "helper; !id",
        }),
      ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
      expect(await session.execute("xrefs", { address: "main" })).toMatchObject(
        {
          ok: false,
          error: {
            _tag: "AnalysisInputError",
            issues: [{ path: ["address"], reason: "invalid_format" }],
          },
        },
      );
      expect(
        await session.execute("list_procedures", { document: "other.elf" }),
      ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
    });
  });
}
