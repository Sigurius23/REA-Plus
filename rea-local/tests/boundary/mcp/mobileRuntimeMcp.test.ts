import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished, vi } from "vitest";

import type { MobileRuntimeAnalysisPort } from "../../../src/application/mobileRuntime/MobileRuntimeAnalysisPort.js";
import type { MobileRuntimeRequest } from "../../../src/domain/mobileRuntime/mobileRuntimeAnalysis.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import { MOBILE_RUNTIME_TOOL_CONTRACTS } from "../../../src/contracts/mobileRuntime/mobileRuntimeToolContracts.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { assertAdvertisedMcpContracts } from "./mcpContractHarness.js";

const script = "send({ message: 'hello' });";
const providerResult = {
  frida_version: "17.0.1",
  python_executable_sha256: `sha256:${"a".repeat(64)}`,
  device: { id: "usb", name: "USB device", type: "usb" },
  process: { pid: 1234, name: "sample.app" },
  script_sha256: `sha256:${"b".repeat(64)}`,
  script_bytes: Buffer.byteLength(script, "utf8"),
  observation_ms: 1000,
  messages: [],
  omitted_message_count: 0,
  messages_truncated: false,
  script_unloaded: true,
  detached: true,
};

it("registers runtime tools, enforces confirmation, and returns digest-only Evidence parameters", async () => {
  const execute = vi.fn(async (request: MobileRuntimeRequest) => {
    expect(request.operation).toBe("run_frida_script");
    return ok({
      result: providerResult,
      provider: { id: "frida", name: "Frida", version: "17.0.1" },
      limitations: ["test provider"],
    });
  });
  const provider: MobileRuntimeAnalysisPort = {
    execute,
    async close() {},
  };
  const server = createServer(
    {
      kind: "session",
      session: createTestBinarySession(() => {
        throw new Error("deep analysis must not start");
      }),
    },
    { mobileRuntimeAnalysis: provider },
  );
  onTestFinished(() => server.close());
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({
    name: "runtime-instrumentation",
    version: "0.0.0",
  });
  onTestFinished(() => client.close());
  await client.connect(clientTransport);

  const { tools } = await client.listTools();
  const names = MOBILE_RUNTIME_TOOL_CONTRACTS.map(({ name }) => name);
  expect(TOOL_CONTRACTS.map(({ name }) => name)).toEqual(
    expect.arrayContaining(names),
  );
  assertAdvertisedMcpContracts(names, tools);

  const unconfirmed = await client.callTool({
    name: "run_frida_script",
    arguments: {
      pid: 1234,
      script,
      observation_ms: 1000,
    },
  });
  expect(unconfirmed.isError).toBe(true);
  expect(execute).not.toHaveBeenCalled();

  const observed = await client.callTool({
    name: "run_frida_script",
    arguments: {
      pid: 1234,
      script,
      observation_ms: 1000,
      confirm_runtime_code_execution: true,
    },
  });
  expect(observed.isError).not.toBe(true);
  const text = (observed.content as { readonly text?: string }[])
    .map((part) => part.text ?? "")
    .join("");
  const evidence = parseEvidence(JSON.parse(text));
  expect(evidence.provider).toEqual({
    id: "frida",
    name: "Frida",
    version: "17.0.1",
  });
  expect(evidence.subject).toBeNull();
  expect(evidence.parameters).not.toHaveProperty("script");
  expect(JSON.stringify(evidence.parameters)).not.toContain(script);
  expect(evidence.limitations).toContain("test provider");
  expect(execute).toHaveBeenCalledTimes(1);
});
