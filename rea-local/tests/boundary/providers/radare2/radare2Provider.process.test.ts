import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { AnalysisProviderRegistry } from "../../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../../src/application/binary/BinarySessionComposition.js";
import { parseBinaryTarget } from "../../../../src/application/BinaryTargetResolver.js";
import { parseConfig } from "../../../../src/config/parseConfig.js";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
} from "../../../../src/process/ProviderProcess.js";
import { Radare2Provider } from "../../../../src/radare2/Radare2Provider.js";
import {
  createRadare2Elf,
  RADARE2_ELF_LAYOUT as LAYOUT,
} from "../../../fixtures/radare2Elf.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const FAKE_RADARE2 = fileURLToPath(
  new URL("../../../fixtures/fakeRadare2.mjs", import.meta.url),
);
const FAKE_RIZIN = fileURLToPath(
  new URL("../../../fixtures/fakeRizin.mjs", import.meta.url),
);

/**
 * Route every radare2 launch to the recorded fake. Each pipe session takes the
 * next scenario; the last one repeats. Version probes are not sessions.
 */
const fakeLauncher = (
  scenarios: readonly string[],
  environment: Readonly<Record<string, string>> = {},
  fake = FAKE_RADARE2,
) => {
  const sessions: string[] = [];
  const launch = (options: OwnedProviderProcessSpawnOptions) => {
    const session = options.arguments.includes("-q0");
    const scenario = session
      ? (scenarios[Math.min(sessions.length, scenarios.length - 1)] ?? "ready")
      : "ready";
    if (session) sessions.push(scenario);
    return spawnOwnedProviderProcess({
      ...options,
      command: process.execPath,
      arguments: [fake, ...options.arguments],
      hostEnvironment: {
        ...options.hostEnvironment,
        ...environment,
        REA_FAKE_RADARE2_SCENARIO: scenario,
      },
    });
  };
  return { launch, sessions };
};

const createFixture = async (
  scenarios: readonly string[],
  settings: Readonly<Record<string, string>> = {},
  environment: Readonly<Record<string, string>> = {},
  fake = FAKE_RADARE2,
) => {
  const root = await createTestTempDirectory("rea-radare2-process-");
  const runtime = join(root, "runtime");
  await mkdir(runtime);
  const path = join(root, "fixture.elf");
  await writeFile(path, createRadare2Elf());
  // The configured path must be executable; the launcher seam replaces it.
  const config = parseConfig({
    REA_RADARE2_PATH: process.execPath,
    ...settings,
  });
  if (!config.ok) throw config.error;
  const launcher = fakeLauncher(scenarios, environment, fake);
  const provider = new Radare2Provider(config.value, process.env, {
    launcher: launcher.launch,
    runtimeParent: runtime,
  });
  const session = composeBinarySession(
    new AnalysisProviderRegistry([provider], "radare2"),
  );
  return { path, runtime, provider, session, launcher };
};

describe("radare2 provider process lifecycle", () => {
  it("stops a hung analysis on cancellation, removes its private copy and restarts on the next call", async () => {
    const { path, runtime, session, launcher } = await createFixture([
      "hang-analysis",
      "ready",
    ]);
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    const controller = new AbortController();
    const pending = session.execute(
      "list_procedures",
      {},
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(), 200);
    expect(await pending).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError", operation: "list_procedures" },
    });
    await expect(readdir(runtime)).resolves.toEqual([]);

    const recovered = await session.execute("list_procedures", {});
    if (!recovered.ok) throw recovered.error;
    expect(recovered.value.result).toEqual([
      { address: `0x${LAYOUT.start.toString(16)}`, value: "entry0" },
      { address: `0x${LAYOUT.checkKey.toString(16)}`, value: "sym.check_key" },
      { address: `0x${LAYOUT.helper.toString(16)}`, value: "sym.helper" },
    ]);
    expect(launcher.sessions).toEqual(["hang-analysis", "ready"]);
    expect((await session.close()).ok).toBe(true);
    await expect(readdir(runtime)).resolves.toEqual([]);
  });

  it("reports a crashed radare2 with its stderr and recovers with a fresh process", async () => {
    const { path, session, launcher } = await createFixture([
      "exit-analysis",
      "ready",
    ]);
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    const failed = await session.execute("list_procedures", {});
    expect(failed).toMatchObject({
      ok: false,
      error: {
        _tag: "ProviderAdapterError",
        providerId: "radare2",
        diagnostics: {
          command: "aaa",
          stderr: expect.stringContaining("fake radare2 analysis crashed"),
        },
      },
    });
    expect((await session.execute("list_procedures", {})).ok).toBe(true);
    expect(launcher.sessions).toEqual(["exit-analysis", "ready"]);
    expect((await session.close()).ok).toBe(true);
  });

  it("enforces the configured analysis deadline", async () => {
    const { path, runtime, session } = await createFixture(["hang-analysis"], {
      REA_RADARE2_ANALYSIS_TIMEOUT_MS: "300",
    });
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    expect(await session.execute("list_procedures", {})).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisTimeoutError", timeoutMs: 300 },
    });
    await expect(readdir(runtime)).resolves.toEqual([]);
    expect((await session.close()).ok).toBe(true);
  });

  it("refuses an executable whose version changed after profile resolution", async () => {
    const { path, session } = await createFixture(["version-drift"]);
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    expect(await session.execute("list_procedures", {})).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisProtocolError",
        message: expect.stringContaining("committed 6.2.4"),
      },
    });
    expect((await session.close()).ok).toBe(true);
  });

  it("rejects radare2 releases outside the supported 6.x line before any session", async () => {
    const { path, provider, launcher } = await createFixture(
      ["ready"],
      {},
      { REA_FAKE_RADARE2_VERSION: "5.9.8" },
    );
    const target = await parseBinaryTarget(path);
    if (!target.ok) throw target.error;
    expect(await provider.resolveAnalysisProfile(target.value)).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        reason: expect.stringContaining("radare2 5.9.8 is outside"),
      },
    });
    expect(launcher.sessions).toEqual([]);
  });

  it("commits the engine version and analysis level in its profile", async () => {
    const { path, provider } = await createFixture(["ready"], {
      REA_RADARE2_ANALYSIS: "aa",
    });
    const target = await parseBinaryTarget(path);
    if (!target.ok) throw target.error;
    const resolved = await provider.resolveAnalysisProfile(target.value);
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile).toMatchObject({
      provider: { id: "radare2", version: "1" },
      parameters: {
        engine_version: "6.2.4",
        engine_commit: "485e5e205b190fc297a2a95a6f982ff5d9f54039",
        analysis_level: "aa",
        cache_policy: "snapshot",
      },
    });
  });
});

describe("radare2 provider with Rizin's dialect", () => {
  const hex = (value: number) => `0x${value.toString(16)}`;

  it("commits the Rizin engine and arguments without radare2-only settings", async () => {
    const { path, provider } = await createFixture(
      ["ready"],
      {},
      {},
      FAKE_RIZIN,
    );
    const target = await parseBinaryTarget(path);
    if (!target.ok) throw target.error;
    const resolved = await provider.resolveAnalysisProfile(target.value);
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile.parameters).toMatchObject({
      engine: "rizin",
      engine_version: "0.9.1",
      engine_commit: "c3a90e9226d977f58f4e9c75f78fa6b07afe13c7",
      process_arguments: [
        "-N",
        "-q0",
        "-e",
        "scr.color=0",
        "-e",
        "scr.utf8=false",
        "-e",
        "scr.interactive=false",
      ],
    });
  });

  it("rejects Rizin releases outside the supported 0.9 line", async () => {
    const { path, provider, launcher } = await createFixture(
      ["ready"],
      {},
      { REA_FAKE_RADARE2_VERSION: "0.8.1" },
      FAKE_RIZIN,
    );
    const target = await parseBinaryTarget(path);
    if (!target.ok) throw target.error;
    expect(await provider.resolveAnalysisProfile(target.value)).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        reason: expect.stringContaining("rizin 0.8.1 is outside"),
      },
    });
    expect(launcher.sessions).toEqual([]);
  });

  it("refuses a Rizin whose ver reply drifted from the profile", async () => {
    const { path, session } = await createFixture(
      ["version-drift"],
      {},
      {},
      FAKE_RIZIN,
    );
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    expect(await session.execute("list_procedures", {})).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisProtocolError",
        message: expect.stringContaining(
          "rizin executable reported 0.9.0 but the analysis profile committed 0.9.1",
        ),
      },
    });
    expect((await session.close()).ok).toBe(true);
  });

  it("normalizes Rizin's replies into the provider's results", async () => {
    const { path, runtime, session } = await createFixture(
      ["ready"],
      {},
      {},
      FAKE_RIZIN,
    );
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    const run = async (
      operation: Parameters<typeof session.execute>[0],
      input: Record<string, string | number> = {},
    ) => {
      const result = await session.execute(operation, input);
      if (!result.ok) throw result.error;
      return result.value;
    };
    const procedures = await run("list_procedures");
    expect(procedures.rawResult).toMatchObject({ engine: "rizin" });
    expect(procedures.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Rizin has no command sandbox"),
      ]),
    );
    expect(procedures.result).toEqual([
      { address: hex(LAYOUT.start), value: "entry0" },
      { address: hex(LAYOUT.checkKey), value: "main" },
      { address: hex(LAYOUT.helper), value: "sym.helper" },
    ]);
    // axtj names no function, so the caller is resolved through afij and afbj.
    expect(
      await run("procedure_callers", { procedure: "helper" }),
    ).toMatchObject({
      result: [hex(LAYOUT.checkKey)],
      rawResult: {
        commands: [
          "isj",
          "axtj @ 0x40011b",
          "afij @ 0x400115",
          "afbj @ 0x40010e",
        ],
      },
    });
    // The flag name still selects the function Rizin calls main.
    expect(
      await run("procedure_callees", { procedure: "sym.check_key" }),
    ).toMatchObject({
      result: [hex(LAYOUT.helper)],
      rawResult: { commands: ["afij @ 0x40010e"] },
    });
    expect(
      (await run("procedure_info", { procedure: "check_key" })).result,
    ).toMatchObject({ name: "main", locals: [], length: 13 });
    // omlj lists the file map first with an exclusive end.
    expect(
      (await run("read_bytes", { address: hex(LAYOUT.helper), length: 5 }))
        .result,
    ).toMatchObject({ bytes_hex: LAYOUT.helperBytes, complete: true });
    expect(
      (await run("read_bytes", { address: hex(LAYOUT.bss), length: 4 })).result,
    ).toMatchObject({ returned_bytes: 0, complete: false });
    expect(
      await session.execute("procedure_pseudo_code", { procedure: "main" }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
    expect((await session.close()).ok).toBe(true);
    await expect(readdir(runtime)).resolves.toEqual([]);
  });
});
