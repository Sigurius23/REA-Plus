import { access, readFile } from "node:fs/promises";
import { expect, it } from "vitest";

import type { MobileRuntimeRequest } from "../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import type { MobileRuntimeCommandRunner } from "./MobileRuntimeProvider.js";
import { MobileRuntimeProvider } from "./MobileRuntimeProvider.js";

const helperOutput = (result: Readonly<Record<string, unknown>>) => ({
  stdout: `__REA_FRIDA_JSON__${JSON.stringify({ ok: true, result })}\n`,
  stderr: "",
  stdoutBytes: 0,
  stderrBytes: 0,
  exitCode: 0,
  signal: null,
});

it("MobileRuntimeProvider uses a private request file and records only a digest for a confirmed Frida script", async () => {
  let requestPath = "";
  const runner: MobileRuntimeCommandRunner = {
    async run(command, args, options) {
      expect(command).toBe(process.execPath);
      expect(args).toHaveLength(2);
      requestPath = args[1]!;
      const request = JSON.parse(await readFile(requestPath, "utf8")) as {
        operation: string;
        script: string;
        pid: number;
      };
      expect(request).toMatchObject({
        operation: "run_script",
        pid: 1234,
        script: "send({ message: 'hello' });",
      });
      expect(options.acceptNonZeroExit).toBe(true);
      expect(options.timeoutMs).toBe(16_000);
      return helperOutput({
        frida_version: "17.0.1",
        device: { id: "usb", name: "USB device", type: "usb" },
        process: { pid: 1234, name: "sample.app" },
        observation_ms: 1000,
        messages: [],
        omitted_message_count: 0,
        messages_truncated: false,
        script_unloaded: true,
        detached: true,
      });
    },
  };
  const provider = new MobileRuntimeProvider({
    environment: { REA_FRIDA_PYTHON_PATH: process.execPath },
    commandRunner: runner,
  });
  const result = await provider.execute({
    operation: "run_frida_script",
    input: {
      pid: 1234,
      script: "send({ message: 'hello' });",
      observation_ms: 1000,
      confirm_runtime_code_execution: true,
    },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.provider).toEqual({
    id: "frida",
    name: "Frida",
    version: "17.0.1",
  });
  expect(result.value.result).toMatchObject({
    script_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
    script_bytes: Buffer.byteLength("send({ message: 'hello' });", "utf8"),
    python_executable_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
    process: { pid: 1234, name: "sample.app" },
  });
  expect(
    await access(requestPath).then(
      () => true,
      () => false,
    ),
  ).toBe(false);
  await provider.close();
});

it("MobileRuntimeProvider uses Objection's one-shot run syntax without a host shell", async () => {
  const runner: MobileRuntimeCommandRunner = {
    async run(command, args, options) {
      expect(command).toBe(process.execPath);
      expect(args).toEqual([
        "--name",
        "com.example.app",
        "--serial",
        "usb-1",
        "run",
        "env",
      ]);
      expect(options.acceptNonZeroExit).toBe(true);
      return {
        stdout: "Android version: 14\n",
        stderr: "",
        stdoutBytes: Buffer.byteLength("Android version: 14\n", "utf8"),
        stderrBytes: 0,
        exitCode: 0,
        signal: null,
      };
    },
  };
  const provider = new MobileRuntimeProvider({
    environment: { REA_OBJECTION_CMD_PATH: process.execPath },
    commandRunner: runner,
  });
  const result = await provider.execute({
    operation: "run_objection_command",
    input: {
      target: "com.example.app",
      device_serial: "usb-1",
      command: "env",
      timeout_ms: 1000,
      confirm_runtime_command_execution: true,
    },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.provider).toEqual({
    id: "objection",
    name: "Objection",
    version: null,
  });
  expect(result.value.result).toMatchObject({
    target: "com.example.app",
    device_serial: "usb-1",
    stdout: "Android version: 14\n",
    exit_code: 0,
    timed_out: false,
    executable_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
  });
  await provider.close();
});

it("MobileRuntimeProvider cancels active commands and drains them before close resolves", async () => {
  let observedSignal: AbortSignal | undefined;
  let started!: () => void;
  const hasStarted = new Promise<void>((resolve) => {
    started = resolve;
  });
  const runner: MobileRuntimeCommandRunner = {
    async run(_command, _args, options) {
      observedSignal = options.signal;
      started();
      await new Promise<void>((resolve) => {
        options.signal?.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      throw new Error("runner stopped");
    },
  };
  const provider = new MobileRuntimeProvider({
    environment: { REA_OBJECTION_CMD_PATH: process.execPath },
    commandRunner: runner,
  });
  const operation = provider.execute({
    operation: "run_objection_command",
    input: {
      target: "com.example.app",
      command: "env",
      timeout_ms: 1000,
      confirm_runtime_command_execution: true,
    },
  });
  await hasStarted;
  await provider.close();
  expect(observedSignal?.aborted).toBe(true);
  expect(await operation).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it.each([
  {
    operation: "run_frida_script",
    input: { pid: 1234, script: "send('x')", observation_ms: 1000 },
  },
  {
    operation: "run_frida_script",
    input: {
      pid: 1234,
      script: "send('x')",
      observation_ms: 1000,
      confirm_runtime_code_execution: false,
    },
  },
  {
    operation: "run_objection_command",
    input: { target: "com.example.app", command: "env", timeout_ms: 1000 },
  },
  {
    operation: "run_objection_command",
    input: {
      target: "com.example.app",
      command: "env",
      timeout_ms: 1000,
      confirm_runtime_command_execution: false,
    },
  },
])(
  "rejects direct unconfirmed $operation requests before launching a command",
  async (request) => {
    let runCount = 0;
    const provider = new MobileRuntimeProvider({
      environment: {
        REA_FRIDA_PYTHON_PATH: process.execPath,
        REA_OBJECTION_CMD_PATH: process.execPath,
      },
      commandRunner: {
        async run() {
          runCount += 1;
          throw new Error("unconfirmed runtime operation must not launch");
        },
      },
    });

    const result = await provider.execute(
      request as unknown as MobileRuntimeRequest,
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    expect(runCount).toBe(0);
    await provider.close();
  },
);
