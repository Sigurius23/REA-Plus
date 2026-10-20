import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Il2CppMetadataService } from "../../../../src/application/il2cpp/Il2CppMetadataService.js";
import { R2UnityMetadataProvider } from "../../../../src/il2cpp/R2UnityMetadataProvider.js";
import { PrivateRuntimeRoot } from "../../../../src/process/PrivateRuntimeRoot.js";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
} from "../../../../src/process/ProviderProcess.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";
import {
  describeIl2CppViews,
  inspectReport,
  writeIl2CppFixtures,
  type Il2CppLaneFiles,
} from "./il2cppLane.js";

const FAKE_R2UNITY = fileURLToPath(
  new URL("../../../fixtures/fakeR2unity.mjs", import.meta.url),
);

/** Route every r2unity launch to the recorded fake and log its arguments. */
const fakeLauncher = () => {
  const state = { scenario: "ready", runs: [] as string[][] };
  const launch = (options: OwnedProviderProcessSpawnOptions) => {
    state.runs.push([...options.arguments]);
    return spawnOwnedProviderProcess({
      ...options,
      command: process.execPath,
      arguments: [FAKE_R2UNITY, ...options.arguments],
      hostEnvironment: {
        ...options.hostEnvironment,
        REA_FAKE_R2UNITY_SCENARIO: state.scenario,
      },
    });
  };
  return { launch, state };
};

let root = "";
let runtimeParent = "";
let executable = "";
let files: Il2CppLaneFiles;

/** The configured path must be executable; the launcher seam replaces it. */
const createService = (launcher = fakeLauncher()) => ({
  launcher,
  service: new Il2CppMetadataService(
    new R2UnityMetadataProvider(
      { ...process.env, REA_R2UNITY_PATH: executable },
      launcher.launch,
      () => PrivateRuntimeRoot.create({ parent: runtimeParent }),
    ),
  ),
});

beforeAll(async () => {
  root = (await createTestWorkspace("rea-r2unity-process-")).root;
  runtimeParent = join(root, "runtime");
  await mkdir(runtimeParent);
  files = await writeIl2CppFixtures(root);
  executable = join(root, "r2unity");
  await writeFile(executable, "#!/bin/sh\nexit 70\n", { mode: 0o755 });
});
afterAll(async () => {
  await expect(readdir(runtimeParent)).resolves.toEqual([]);
  await removeTestWorkspace(root);
});

describe("recorded r2unity 1.2.8 lane", () => {
  let service: Il2CppMetadataService;
  beforeAll(() => {
    service = createService().service;
  });
  afterAll(() => service.close());
  describeIl2CppViews(() => ({ service, files }));
});

describe("r2unity process lifecycle", () => {
  it("probes the version once and reruns nothing for cached pages", async () => {
    const { service, launcher } = createService();
    try {
      await inspectReport(service, { metadata_path: files.metadata });
      await inspectReport(service, {
        metadata_path: files.metadata,
        query: "Player",
      });
      const literals = await inspectReport(service, {
        metadata_path: files.metadata,
        view: "string_literals",
      });
      expect(literals.tool_profile.cached).toBe(false);
      expect(launcher.state.runs.map((args) => args.slice(0, 3))).toEqual([
        ["-v"],
        ["-c", "-j", expect.stringMatching(/^target-[0-9a-f]{12}\.dat$/u)],
        ["-c", "-j", "-l"],
        ["-q", "-z", expect.stringMatching(/^target-/u)],
      ]);
    } finally {
      await service.close();
    }
  });

  it("refuses an unsupported r2unity release before reading files", async () => {
    const launcher = fakeLauncher();
    launcher.state.scenario = "version-drift";
    const { service } = createService(launcher);
    expect(
      await service.inspect({ metadata_path: files.metadata }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "r2unity-il2cpp-metadata",
        userMessage: expect.stringContaining("r2unity 1.3.0"),
      },
    });
    expect(launcher.state.runs).toEqual([["-v"]]);
  });

  it.each([
    ["malformed", /admitted 1\.2 shape/u],
    ["crash", /r2unity failed/u],
  ])("fails closed on %s output", async (scenario, message) => {
    const launcher = fakeLauncher();
    const { service } = createService(launcher);
    await inspectReport(service, {
      metadata_path: files.metadata,
      view: "assemblies",
    });
    launcher.state.scenario = scenario;
    const result = await service.inspect({ metadata_path: files.metadata });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
    if (!result.ok) expect(result.error.message).toMatch(message);
    await service.close();
  });

  it("cancels a running listing and removes its workspace", async () => {
    const launcher = fakeLauncher();
    const { service } = createService(launcher);
    await inspectReport(service, {
      metadata_path: files.metadata,
      view: "interop",
    });
    launcher.state.scenario = "hang";
    const controller = new AbortController();
    const pending = service.inspect(
      { metadata_path: files.metadata },
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(), 300);
    expect(await pending).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    await expect(readdir(runtimeParent)).resolves.toEqual([]);
    await service.close();
  });

  it("reports an unconfigured r2unity as unavailable", async () => {
    const service = new Il2CppMetadataService(new R2UnityMetadataProvider({}));
    expect(
      await service.inspect({ metadata_path: files.metadata }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("REA_R2UNITY_PATH"),
      },
    });
  });
});
