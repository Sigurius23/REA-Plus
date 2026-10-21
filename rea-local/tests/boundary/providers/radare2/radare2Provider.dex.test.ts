import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AnalysisProviderRegistry } from "../../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../../src/application/binary/BinarySessionComposition.js";
import { parseConfig } from "../../../../src/config/parseConfig.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import { Radare2Provider } from "../../../../src/radare2/Radare2Provider.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

type Session = Awaited<ReturnType<typeof openDexSession>>;

const executable = process.env["REA_VERIFY_RADARE2_PATH"];
const DEX_FIXTURE = new URL(
  "../../../fixtures/dex/classes.dex",
  import.meta.url,
);

/**
 * The checked-in `tests/fixtures/dex/classes.dex` holds one class
 * (`com.rea.fixture.Fixture`) built from the sibling `Fixture.java` with
 * `javac --release 17 Fixture.java && d8 --release --min-api 21
 * --output . Fixture.class`. radare2 names DEX methods from their class
 * and descriptor (`method.<modifiers>.<class>.<class>.method.<name>`).
 */
const CHECK_KEY =
  "method.public.static.Lcom_rea_fixture_Fixture.Lcom_rea_fixture_Fixture.method.checkKey_I_I";
const CHECK_KEY_ADDRESS = "0x128";
const SECRET = "rea-dex-secret-42";

const openDexSession = async (root: string, runtime: string) => {
  await writeFile(join(root, "classes.dex"), await readFile(DEX_FIXTURE));
  const config = parseConfig({
    REA_ANALYSIS_PROVIDER: "radare2",
    REA_RADARE2_PATH: executable ?? "",
  });
  if (!config.ok) throw config.error;
  const provider = new Radare2Provider(config.value, process.env, {
    runtimeParent: runtime,
  });
  const session = composeBinarySession(
    new AnalysisProviderRegistry([provider], "radare2"),
  );
  const opened = await session.open(join(root, "classes.dex"));
  if (!opened.ok) throw opened.error;
  return session;
};

describe.skipIf(executable === undefined)(
  "real radare2 provider over a DEX fixture (set REA_VERIFY_RADARE2_PATH to radare2 6.x)",
  () => {
    let session: Session | undefined;
    let root: string;
    let runtime: string;

    beforeAll(async () => {
      const workspace = await createTestWorkspace("rea-radare2-dex-");
      root = workspace.root;
      runtime = join(root, "runtime");
      await mkdir(runtime);
      session = await openDexSession(root, runtime);
    });

    afterAll(async () => {
      if (session === undefined) return;
      try {
        expect((await session.close()).ok).toBe(true);
        await expect(readdir(runtime)).resolves.toEqual([]);
      } finally {
        await removeTestWorkspace(root);
      }
    });

    /** Fails the test body when the fixture session did not open. */
    const fixtureSession = (): Session => {
      if (session === undefined) throw new Error("session did not open");
      return session;
    };

    const run = async (
      operation: Parameters<Session["execute"]>[0],
      input: Readonly<Record<string, JsonValue>> = {},
    ) => {
      const result = await fixtureSession().execute(operation, input);
      if (!result.ok) throw result.error;
      return result.value;
    };

    it("admits the DEX as a Dalvik target and analyzes every method", async () => {
      const procedures = await run("list_procedures");
      expect(procedures.provider.id).toBe("radare2");
      expect(procedures.analysisProfile?.parameters).toMatchObject({
        engine: "radare2",
        // DEX analysis defaults to `aa`; every DEX method already has a flag.
        analysis_level: "aa",
      });
      expect(procedures.result).toEqual(
        expect.arrayContaining([expect.objectContaining({ value: CHECK_KEY })]),
      );
    });

    it("resolves the method by name and describes its body", async () => {
      expect(
        (await run("procedure_address", { procedure: CHECK_KEY })).result,
      ).toBe(CHECK_KEY_ADDRESS);
      expect(
        (await run("procedure_info", { procedure: CHECK_KEY })).result,
      ).toMatchObject({
        name: CHECK_KEY,
        entrypoint: CHECK_KEY_ADDRESS,
      });
    });

    it("lists and searches the data-section strings", async () => {
      const strings = (await run("list_strings")).result as Readonly<
        Record<string, unknown>
      >[];
      expect(strings).toEqual(
        expect.arrayContaining([expect.objectContaining({ value: SECRET })]),
      );
      // Searches also match string constant names: the static field SECRET
      // and its runtime value rea-dex-secret-42 share the substring.
      expect(
        (await run("search_strings", { pattern: "secret" })).result,
      ).toEqual([
        { address: "0x1f2", value: "SECRET" },
        { address: "0x20f", value: SECRET },
      ]);
    });
  },
);
