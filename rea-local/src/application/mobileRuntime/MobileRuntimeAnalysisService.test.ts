import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import type { MobileRuntimeAnalysisPort } from "./MobileRuntimeAnalysisPort.js";
import { MobileRuntimeAnalysisService } from "./MobileRuntimeAnalysisService.js";
import type { MobileRuntimeRequest } from "../../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import { parseEvidence } from "../../domain/evidence.js";
import { ok } from "../../domain/result.js";

const script = "send({ message: 'private script source' });";
const scriptDigest = `sha256:${createHash("sha256").update(script).digest("hex")}`;

const observation = {
  result: {
    frida_version: "17.0.1",
    python_executable_sha256: `sha256:${"a".repeat(64)}`,
    device: { id: "usb", name: "USB device", type: "usb" },
    process: { pid: 1234, name: "sample.app" },
    script_sha256: scriptDigest,
    script_bytes: Buffer.byteLength(script, "utf8"),
    observation_ms: 1000,
    messages: [],
    omitted_message_count: 0,
    messages_truncated: false,
    script_unloaded: true,
    detached: true,
  },
  provider: { id: "frida", name: "Frida", version: "17.0.1" },
  limitations: ["Caller-selected runtime provider."],
};

describe("MobileRuntimeAnalysisService", () => {
  it("requires explicit confirmation before executing Frida or Objection runtime code", async () => {
    const execute = vi.fn(async () => ok(observation));
    const provider: MobileRuntimeAnalysisPort = {
      execute,
      async close() {},
    };
    const service = new MobileRuntimeAnalysisService(provider);
    const result = await service.execute("run_frida_script", {
      pid: 1234,
      script,
      observation_ms: 1000,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    const objection = await service.execute("run_objection_command", {
      target: "com.example.app",
      command: "env",
    });
    expect(objection).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("records script provenance without persisting its source text in Evidence parameters", async () => {
    const execute = vi.fn(async (request: MobileRuntimeRequest) => {
      expect(request).toMatchObject({
        operation: "run_frida_script",
        input: {
          pid: 1234,
          script,
          observation_ms: 1000,
          confirm_runtime_code_execution: true,
        },
      });
      return ok(observation);
    });
    const service = new MobileRuntimeAnalysisService({
      execute,
      async close() {},
    });
    const result = await service.execute("run_frida_script", {
      pid: 1234,
      script,
      observation_ms: 1000,
      confirm_runtime_code_execution: true,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    const evidence = parseEvidence(result.value);
    expect(evidence.subject).toBeNull();
    expect(evidence.provider).toEqual({
      id: "frida",
      name: "Frida",
      version: "17.0.1",
    });
    expect(evidence.parameters).toEqual({
      device_id: null,
      pid: 1234,
      script_sha256: scriptDigest,
      script_bytes: Buffer.byteLength(script, "utf8"),
      observation_ms: 1000,
      runtime_code_execution_confirmed: true,
    });
    expect(JSON.stringify(evidence.parameters)).not.toContain(script);
    expect(evidence.normalized_result).toMatchObject({
      script_sha256: scriptDigest,
      process: { pid: 1234, name: "sample.app" },
      detached: true,
    });
    expect(evidence.limitations).toContain("Caller-selected runtime provider.");
  });
});
