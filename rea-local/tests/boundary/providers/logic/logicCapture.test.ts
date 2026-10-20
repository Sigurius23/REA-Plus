import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LogicCaptureService } from "../../../../src/application/logic/LogicCaptureService.js";
import type { LogicCapture } from "../../../../src/domain/logic/logicCapture.js";
import { LogicCaptureInspector } from "../../../../src/logic/LogicCaptureInspector.js";
import { PrivateRuntimeRoot } from "../../../../src/process/PrivateRuntimeRoot.js";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
} from "../../../../src/process/ProviderProcess.js";
import {
  createSigrokSession,
  createStoredZip,
  SIGROK_FIXTURE as F,
} from "../../../fixtures/sigrokSession.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const FAKE_SIGROK = fileURLToPath(
  new URL("../../../fixtures/fakeSigrokCli.mjs", import.meta.url),
);

let root = "";
let runtimeParent = "";
let capture = "";
let executable = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-logic-")).root;
  runtimeParent = join(root, "runtime");
  await mkdir(runtimeParent);
  capture = join(root, "board.sr");
  await writeFile(capture, createSigrokSession());
  executable = join(root, "sigrok-cli");
  await writeFile(executable, "#!/bin/sh\nexit 70\n", { mode: 0o755 });
});
afterAll(async () => {
  await expect(readdir(runtimeParent)).resolves.toEqual([]);
  await removeTestWorkspace(root);
});

/** Route sigrok-cli launches to the recorded fake. */
const fakeLauncher = (scenario = "ready") => {
  const runs: string[][] = [];
  const launch = (options: OwnedProviderProcessSpawnOptions) => {
    runs.push([...options.arguments]);
    return spawnOwnedProviderProcess({
      ...options,
      command: process.execPath,
      arguments: [FAKE_SIGROK, ...options.arguments],
      hostEnvironment: {
        ...options.hostEnvironment,
        REA_FAKE_SIGROK_SCENARIO: scenario,
      },
    });
  };
  return { launch, runs };
};

const serviceFor = (
  sigrok: string | undefined,
  launch?: ReturnType<typeof fakeLauncher>["launch"],
) =>
  new LogicCaptureService(
    new LogicCaptureInspector(
      sigrok === undefined ? {} : { ...process.env, REA_SIGROK_CLI: sigrok },
      launch,
      () => PrivateRuntimeRoot.create({ parent: runtimeParent }),
    ),
  );

const inspect = async (
  service: LogicCaptureService,
  input: Record<string, unknown>,
): Promise<LogicCapture> => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as LogicCapture;
};

const UART = {
  id: "uart",
  channels: { rx: "UART_TX" },
  options: { baudrate: F.baud },
};

describe("session statistics without a decoder", () => {
  it("reads chunks in order and estimates the UART bit rate", async () => {
    const report = await inspect(serviceFor(undefined), { path: capture });
    expect(report.capture).toMatchObject({
      sigrok_version: "0.5.2",
      samplerate_hz: F.samplerate,
      samples: 1782,
      duration_s: 0.001782,
      unitsize: 1,
    });
    const [tx, idle, clk] = report.channels;
    expect(tx).toMatchObject({
      name: "UART_TX",
      initial_level: 1,
      final_level: 1,
      first_transition_s: 0.0002,
    });
    expect(
      Math.abs((tx?.estimated_bit_rate ?? 0) - F.baud) / F.baud,
    ).toBeLessThan(0.01);
    expect(idle).toMatchObject({
      transitions: 0,
      high_fraction: 0,
      shortest_pulse_s: null,
      estimated_bit_rate: null,
    });
    // 32 clock cycles at 100 kHz: 64 edges and 5 us pulses.
    expect(clk).toMatchObject({
      transitions: 64,
      shortest_pulse_s: 0.000005,
      estimated_bit_rate: 200000,
    });
    expect(report.analog).toEqual([
      { name: "A0", index: 6, samples: 8, min: 0, max: 3.5, mean: 1.75 },
    ]);
    expect(report.decode).toBeNull();
  });

  it("rejects archives that are not sigrok sessions", async () => {
    const zip = join(root, "plain.zip");
    await writeFile(zip, createStoredZip([["readme.txt", Buffer.from("hi")]]));
    const text = join(root, "notes.txt");
    await writeFile(text, "plain text");
    for (const path of [zip, text])
      expect(await serviceFor(undefined).inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              path: ["path"],
              message: expect.stringContaining("sigrok session"),
            },
          ],
        },
      });
  });
});

/** Decode expectations shared by the recorded and real sigrok-cli lanes. */
const describeDecoding = (
  lane: string,
  service: () => LogicCaptureService,
): void => {
  describe(lane, () => {
    it("recovers the UART text as a byte stream", async () => {
      const report = await inspect(service(), {
        path: capture,
        decoders: [UART],
        annotations: ["rx-data", "rx-warnings"],
        annotation_limit: 2,
      });
      expect(report.decode).toMatchObject({
        stack: [`uart:rx=UART_TX:baudrate=${String(F.baud)}`],
        annotations: [
          {
            class: "rx-data",
            decoder: "uart-1",
            start_sample: 209,
            end_sample: 279,
            start_s: 0.000209,
            text: "48",
          },
          { class: "rx-data", text: "65" },
        ],
        totals: [
          { class: "rx-data", total: 12, returned: 2 },
          { class: "rx-warnings", total: 0, returned: 0 },
        ],
        byte_streams: [
          {
            class: "rx-data",
            bytes: 12,
            hex: Buffer.from(F.uartText).toString("hex"),
            text: F.uartText,
            truncated: false,
          },
        ],
        tool_profile: { tool: "sigrok-cli", version: "0.7.2" },
      });
      expect(report.decode?.classes).toContainEqual({
        id: "rx-data",
        description: "RX data",
      });
    });

    it("decodes SPI MOSI bytes from three mapped channels", async () => {
      const report = await inspect(service(), {
        path: capture,
        decoders: [
          { id: "spi", channels: { clk: "CLK", mosi: "MOSI", cs: "CS" } },
        ],
        annotations: ["mosi-data"],
      });
      expect(report.decode?.byte_streams).toEqual([
        {
          class: "mosi-data",
          bytes: 4,
          hex: Buffer.from(F.spiBytes).toString("hex"),
          text: expect.any(String),
          truncated: false,
        },
      ]);
    });

    it("returns unlabelled rows when no classes are selected", async () => {
      const report = await inspect(service(), {
        path: capture,
        decoders: [UART],
        annotation_limit: 3,
      });
      expect(
        report.decode?.annotations.map(({ class: name, text }) => [name, text]),
      ).toEqual([
        [null, "Start bit"],
        [null, "0"],
        [null, "0"],
      ]);
      expect(report.decode?.byte_streams).toEqual([]);
    });

    it("rejects stacks sigrok-cli cannot run before decoding", async () => {
      const cases = [
        [
          { decoders: [{ id: "uart", channels: { rx: "NOPE" } }] },
          "decoders",
          /not an addressable/u,
        ],
        [{ decoders: [{ id: "uart" }] }, "decoders", /at least one channel/u],
        [
          { decoders: [UART, { id: "uart", channels: { rx: "UART_TX" } }] },
          "decoders",
          /Only the bottom decoder/u,
        ],
        [
          { decoders: [UART], annotations: ["no-such"] },
          "annotations",
          /no annotation classes no-such/u,
        ],
        [
          { decoders: [{ id: "nosuch", channels: { rx: "UART_TX" } }] },
          "decoders",
          /Failed to load decoder nosuch/u,
        ],
      ] as const;
      for (const [input, field, message] of cases) {
        const result = await service().inspect({ path: capture, ...input });
        expect(result).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisInputError", issues: [{ path: [field] }] },
        });
        if (!result.ok) expect(JSON.stringify(result.error)).toMatch(message);
      }
    });
  });
};

describeDecoding("recorded sigrok-cli 0.7.2 lane", () =>
  serviceFor(executable, fakeLauncher().launch),
);

describe("sigrok-cli process lifecycle", () => {
  it("treats decoder stderr as a rejection even when sigrok-cli exits 0", async () => {
    const result = await serviceFor(
      executable,
      fakeLauncher("decoder-error").launch,
    ).inspect({ path: capture, decoders: [UART], annotations: ["rx-data"] });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ path: ["decoders"] }] },
    });
    if (!result.ok)
      expect(JSON.stringify(result.error)).toMatch(/Required channel 'clk'/u);
  });

  it("refuses other sigrok-cli releases and missing configuration", async () => {
    const drift = fakeLauncher("version-drift");
    expect(
      await serviceFor(executable, drift.launch).inspect({
        path: capture,
        decoders: [UART],
      }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("sigrok-cli 0.8.0"),
      },
    });
    expect(drift.runs).toEqual([["--version"]]);
    expect(
      await serviceFor(undefined).inspect({ path: capture, decoders: [UART] }),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("REA_SIGROK_CLI"),
      },
    });
  });

  it("cancels a running decoder and removes its workspace", async () => {
    const controller = new AbortController();
    const pending = serviceFor(executable, fakeLauncher("hang").launch).inspect(
      { path: capture, decoders: [UART] },
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(), 300);
    expect(await pending).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    await expect(readdir(runtimeParent)).resolves.toEqual([]);
  });
});

const configured = process.env.REA_VERIFY_SIGROK_CLI;
const SIGROK =
  configured === undefined || configured.length === 0 ? undefined : configured;

describe.skipIf(SIGROK === undefined)(
  "real sigrok-cli (set REA_VERIFY_SIGROK_CLI)",
  () => {
    describeDecoding("real sigrok-cli 0.7 lane", () => serviceFor(SIGROK));
  },
);
