import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createMinidumpService } from "../../../../src/composition/minidump.js";
import type { Minidump } from "../../../../src/domain/minidump/minidump.js";
import {
  createMinidump,
  MINIDUMP_FIXTURE as F,
  moduleCountRva,
} from "../../../fixtures/minidumpFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createMinidumpService();
let root = "";

beforeAll(async () => {
  root = (await createTestWorkspace("rea-minidump-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>): Promise<Minidump> => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as Minidump;
};

const write = async (name: string, bytes: Buffer) => {
  const path = join(root, name);
  await writeFile(path, bytes);
  return path;
};

const hex = (value: bigint) => `0x${value.toString(16)}`;

describe("synthesized Windows x64 dump", () => {
  it("explains the access violation as module+offset", async () => {
    const path = await write("game.dmp", createMinidump());
    const report = await inspect({ path });
    expect(report).toMatchObject({
      dump: { path, created: "2023-11-14T22:15:00.000Z", flags: "0x1826" },
      system: {
        architecture: "amd64",
        os: "Windows NT",
        os_version: "10.0.22631",
        processors: 8,
        cpu_vendor: "GenuineIntel",
      },
      process: {
        process_id: F.processId,
        created: "2023-11-14T22:13:20.000Z",
      },
      exception: {
        thread_id: F.renderThread,
        code: "0xc0000005",
        name: "EXCEPTION_ACCESS_VIOLATION",
        access: { kind: "write", address: "0x10" },
        instruction_pointer: hex(F.gameBase + 0x1000n),
        instruction_module: {
          module: "C:\\Games\\Example\\game.exe",
          offset: "0x1000",
        },
        registers: { rax: "0x10", rsp: hex(F.renderStack + 8n) },
      },
      memory: { ranges: 2, bytes: 0x200, full_memory: false },
    });
    expect(report.dump.streams.at(-1)).toEqual({
      type: "LinuxMaps",
      bytes: 14,
      status: "not-decoded",
      message: null,
    });
    expect(report.threads).toMatchObject([
      {
        id: F.mainThread,
        name: "MainThread",
        crashed: false,
        instruction_module: {
          module: "C:\\Windows\\System32\\ntdll.dll",
          offset: "0x9d4",
        },
      },
      { id: F.renderThread, name: "RenderThread", crashed: true },
    ]);
    expect(report.selected_thread).toEqual({
      id: F.renderThread,
      registers: expect.objectContaining({ rip: hex(F.gameBase + 0x1000n) }),
      stack_scan: [
        {
          slot: hex(F.renderStack + 0x10n),
          value: hex(F.gameBase + 0x1234n),
          module: "C:\\Games\\Example\\game.exe",
          offset: "0x1234",
        },
      ],
    });
    expect(report.modules[0]).toEqual({
      name: "C:\\Games\\Example\\game.exe",
      base: hex(F.gameBase),
      size: F.gameSize,
      end: hex(F.gameBase + BigInt(F.gameSize)),
      timestamp: "2023-09-12T06:06:56.000Z",
      checksum: "0x00000000",
      file_version: "1.2.3.4",
      product_version: "0.0.0.0",
      code_id: "6500000010000",
      debug: {
        format: "RSDS",
        file: "C:\\build\\game.pdb",
        guid: F.guid,
        age: F.age,
        debug_id: `${F.guid.replaceAll("-", "")}2`,
        build_id: null,
      },
    });
    expect(report.unloaded_modules).toEqual([
      {
        name: "C:\\Games\\Example\\old_plugin.dll",
        base: "0x180000000",
        size: 0x4000,
        timestamp: null,
      },
    ]);
  });

  it("reports another thread on request and rejects unknown threads", async () => {
    const path = await write("select.dmp", createMinidump());
    const main = await inspect({ path, thread_id: F.mainThread });
    expect(main.selected_thread).toMatchObject({
      id: F.mainThread,
      registers: { rip: hex(F.ntdllBase + 0x9d4n) },
      stack_scan: [],
    });
    expect(await service.inspect({ path, thread_id: 999 })).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ path: ["thread_id"] }] },
    });
  });

  it("keeps decoding when one stream is malformed", async () => {
    const dump = createMinidump();
    dump.writeUInt32LE(0xffff, moduleCountRva(dump));
    const report = await inspect({
      path: await write("bad-modules.dmp", dump),
    });
    expect(report.modules).toEqual([]);
    expect(
      report.dump.streams.find(({ type }) => type === "ModuleList"),
    ).toMatchObject({ status: "malformed" });
    expect(report.exception).toMatchObject({
      name: "EXCEPTION_ACCESS_VIOLATION",
      instruction_module: null,
    });
    const text = await write("notes.txt", Buffer.from("not a dump"));
    expect(await service.inspect({ path: text })).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ path: ["path"] }] },
    });
  });
});

const configured = process.env.REA_VERIFY_MINIDUMP_DIR;
const SAMPLES =
  configured === undefined || configured.length === 0 ? undefined : configured;

/**
 * rust-minidump's testdata, with expectations cross-checked against
 * minidump-stackwalk 0.27.0: exception, crashing thread, faulting
 * module+offset, thread and module counts, and the first module's debug id.
 */
const REAL_DUMPS = [
  {
    file: "test.dmp",
    sha256: "24b0ea7794b2d2523c46c9aea72c03ccbb0ab88ad76d8258d3752c7b71d233ff",
    os: "Windows NT",
    architecture: "x86",
    exception: "EXCEPTION_ACCESS_VIOLATION",
    thread: 3060,
    module: "c:\\test_app.exe",
    offset: "0x429e",
    threads: 2,
    modules: 13,
    debugId: "5A9832E5287241C1838ED98914E9B7FF1",
    processId: 3932,
  },
  {
    file: "full-dump.dmp",
    sha256: "7e1dd1f116eb648565f50192995c43c222bd33e9a342c0735d13018f688f5a77",
    os: "Windows NT",
    architecture: "amd64",
    exception: "EXCEPTION_BREAKPOINT",
    thread: 8124,
    module: "C:\\Windows\\System32\\ntdll.dll",
    offset: "0xd06b0",
    threads: 4,
    modules: 6,
    debugId: "87D4B19259BC495BA50CC01B85A574641",
    processId: 544,
  },
  {
    file: "invalid-parameter.dmp",
    sha256: "5edaec6b6d8e360c8f26c5907d3ccb29d79cfd4c66d617b23005a2f1396aff9b",
    os: "Windows NT",
    architecture: "amd64",
    exception: "STATUS_INVALID_PARAMETER",
    thread: 5896,
    module: "c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe",
    offset: "0x7a9a3",
    threads: 6,
    modules: 31,
    debugId: "368A7C3A63A644D9BF659B2F4799A1C23",
    processId: 6256,
  },
  {
    file: "linux-mini.dmp",
    sha256: "ec4b64062545eb9874d25037bf0624c96a49098eed20b595344c72d344381576",
    os: "Linux",
    architecture: "amd64",
    exception: "SIGSEGV",
    thread: 1304,
    module: "/work/linux/build/crash",
    offset: "0x1d72",
    threads: 1,
    modules: 8,
    debugId: "C0BCC3F19827FE653058404B2831D9E60",
    processId: null,
  },
  {
    file: "pipeline-inlines-macos-segv.dmp",
    sha256: "9915eb2943ae16e6b6e50cf4bfa5c818032f2c7b3b85e1fa91d5296fad22b707",
    os: "macOS",
    architecture: "amd64",
    exception: "EXC_BAD_ACCESS / KERN_INVALID_ADDRESS",
    thread: 4611,
    module:
      "/Users/ABeingessner/dev/minidump-pipeline/runs/pipeline-inlines/install/bin/crash-client",
    offset: "0x14cd4",
    threads: 11,
    modules: 47,
    debugId: "509C0610949836F7B70BD88BCF03E5400",
    processId: 80556,
  },
  {
    file: "simple-crashpad.dmp",
    sha256: "eeac82c333080aa59a5815424b09eeb7f3f223f8fe18b7c50a361bd9c9d75148",
    os: "macOS",
    architecture: "amd64",
    exception: null,
    thread: 927532,
    module: "/usr/lib/system/libsystem_kernel.dylib",
    offset: "0x733a",
    threads: 1,
    modules: 40,
    debugId: "EF1091E381DA369B9039EA1591D07E0B0",
    processId: 56685,
  },
] as const;

describe.skipIf(SAMPLES === undefined)(
  "real minidumps (set REA_VERIFY_MINIDUMP_DIR to rust-minidump's testdata)",
  () => {
    it.each(REAL_DUMPS)(
      "matches minidump-stackwalk on $file",
      async (sample) => {
        const path = join(SAMPLES ?? "", sample.file);
        const report = await inspect({ path, stack_scan_limit: 8 });
        expect(report.dump.sha256).toBe(sample.sha256);
        expect(report).toMatchObject({
          system: { os: sample.os, architecture: sample.architecture },
          process: { process_id: sample.processId },
          exception: {
            name: sample.exception,
            thread_id: sample.thread,
            instruction_module: {
              module: sample.module,
              offset: sample.offset,
            },
          },
        });
        expect(report.threads).toHaveLength(sample.threads);
        expect(report.threads.filter(({ crashed }) => crashed)).toHaveLength(1);
        expect(report.modules).toHaveLength(sample.modules);
        expect(report.modules[0]?.debug?.debug_id).toBe(sample.debugId);
        expect(report.selected_thread?.id).toBe(sample.thread);
        expect(
          report.dump.streams.every(({ status }) => status !== "malformed"),
        ).toBe(true);
      },
    );

    it("reports fuzzed directories instead of failing", async () => {
      const path = join(SAMPLES ?? "", "invalid-range.dmp");
      if (!existsSync(path)) return;
      const report = await inspect({ path });
      expect(report.exception).toBeNull();
      expect(
        report.dump.streams.filter(({ status }) => status === "malformed")
          .length,
      ).toBeGreaterThan(0);
    });
  },
);
