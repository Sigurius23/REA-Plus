#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  mcpTextValue,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { functionBodySchema } from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Lane input is the committed public source-built fixture: Fixture.java plus
// classes.dex (javac --release 17, d8 --release --min-api 21). No Android SDK
// runtime, emulator or live APK is involved.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-dex.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:dex supports Linux/macOS hosts; verified hosts: darwin arm64.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:dex prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:dex prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const fixturePath = fileURLToPath(
  new URL("../tests/fixtures/dex/classes.dex", import.meta.url),
);
const fixtureSource = fileURLToPath(
  new URL("../tests/fixtures/dex/Fixture.java", import.meta.url),
);
const fixtureBytes = await readFile(fixturePath);
const fixtureText = await readFile(fixtureSource, "utf8");
assert.ok(
  fixtureText.includes("rea-dex-secret-42"),
  "Fixture source lost its string-pool oracle",
);
assert.ok(
  fixtureText.includes("checkKey"),
  "Fixture source lost its method oracle",
);
const hexBytes = (bytes) => {
  assert.equal(typeof bytes, "string");
  return bytes.replace(/\s/gu, "").toLowerCase();
};
// DEX magic + 035 header version, and the pool string appears verbatim.
assert.deepEqual(
  fixtureBytes.subarray(0, 8).toString("hex"),
  "6465780a30333500",
);
assert.ok(
  fixtureBytes.includes(Buffer.from("rea-dex-secret-42", "utf8")),
  "Fixture bytes lost the pool string oracle",
);
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dex-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const targetPath = join(workspace, "classes.dex");
await copyFile(fixturePath, targetPath);
const sha256 = createHash("sha256").update(fixtureBytes).digest("hex");
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-dex-proof", version: "1" });
let opened = false;
let stderr = "";
let report;
const profileAssertions = (profile) => {
  assert.equal(profile.provider.id, "ghidra");
  assert.equal(profile.parameters.target_format, "dex");
  assert.equal(profile.parameters.architecture, "dalvik");
  assert.equal(profile.parameters.import_mode, "ephemeral-source-immutable");
  assert.equal(profile.parameters.loader, "DexLoader");
  assert.equal(profile.parameters.compiler_spec_id, "default");
  assert.equal(profile.parameters.dalvik_dex_version, "035");
  assert.equal(
    profile.parameters.dalvik_language_source,
    "dex-header-version-v1",
  );
  assert.equal(profile.parameters.language_id, "Dalvik:LE:32:DEX_KitKat");
  assert.equal(
    profile.parameters.string_inventory_evidence,
    "dex-string-pool-defined-data-v1",
  );
  assert.equal(
    profile.parameters.function_body_evidence,
    "complete-inclusive-ranges-v1",
  );
};
try {
  await client.connect(transport);
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const target = await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(target.format, "dex");
  assert.equal(target.architecture, "dalvik");
  assert.equal(target.kind, "executable");
  assert.equal(target.sha256, sha256);
  const session = await call("binary_session");
  const profile = session.analysis_provider_binding?.analysis_profile;
  assert.ok(profile, "Public session omitted committed profile");
  profileAssertions(profile);
  assert.equal(session.sha256, sha256);
  assert.equal(session.open, true);

  // Method inventory recovered from the imported DEX: one function per
  // Dalvik method, qualified by class and descriptor.
  const documentName = `target-${sha256.slice(0, 12)}.dex`;
  // Ghidra creates Dalvik methods in a post-analysis phase; wait for the
  // resident session to publish the method inventory.
  let procedures = [];
  for (let attempt = 0; attempt < 30; attempt++) {
    procedures = await call("list_procedures", { document: documentName });
    if (procedures.length >= 3) break;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  assert.ok(Array.isArray(procedures));
  const byName = new Map(procedures.map((item) => [item.value, item.address]));
  const expectedMethods = [
    "com::rea::fixture::Fixture::checkKey",
    "com::rea::fixture::Fixture::helper",
    "com::rea::fixture::Fixture::Fixture",
  ];
  for (const name of expectedMethods) {
    assert.ok(byName.has(name), `Dalvik method ${name} was not discovered`);
    assert.match(byName.get(name), /^0x[0-9a-f]+$/u);
  }
  const facts = {};
  for (const [key, name] of [
    ["checkKey", "com::rea::fixture::Fixture::checkKey"],
    ["helper", "com::rea::fixture::Fixture::helper"],
  ]) {
    const address = byName.get(name);
    const resolved = await call("procedure_address", { procedure: name });
    assert.equal(resolved, address, "Name/entry round-trip drifted");
    const info = await call("procedure_info", { procedure: address });
    assert.equal(info.entrypoint, address);
    const body = functionBodySchema.parse(info.body);
    assert.equal(body.available, true);
    assert.equal(body.provenance, "ghidra-function-body-address-set");
    assert.equal(body.contains_entry, true);
    assert.equal(body.non_contiguous, false);
    assert.ok(body.total_bytes > 0);
    assert.equal(BigInt(body.total_bytes), BigInt(body.span_bytes));
    assert.deepEqual(body.ranges, [
      {
        start: address,
        end: addressTo(address, BigInt(body.total_bytes) - 1n),
      },
    ]);
    const dossierResult = await evidenceCall("analyze_function", {
      procedure: address,
    });
    const dossier = dossierResult.normalized_result;
    assert.ok(
      dossier.pseudocode.trim().length > 0,
      "Real DEX decompilation returned empty pseudocode",
    );
    assert.ok(
      dossier.pseudocode.includes("com::rea::fixture::Fixture"),
      "Decompiled output lost its class provenance",
    );
    assert.deepEqual(dossier.procedure.body, info.body);
    const cli = await cliEvidence("function", address);
    const cliDossier = cli.normalized_result;
    const normalizedDossier = (value) => {
      const { native_value_flow: flow, ...rest } = value;
      assert.ok(flow, "Dossier omitted native value-flow availability");
      return rest;
    };
    assert.deepEqual(
      normalizedDossier(cliDossier),
      normalizedDossier(dossier),
      "CLI/MCP stable DEX dossier observations differ",
    );
    const containing = await call("resolve_containing_procedure", {
      address: address,
    });
    assert.equal(containing.found, true);
    assert.deepEqual(containing.procedure.body, info.body);
    const window = await call("read_function_instructions", {
      procedure: address,
    });
    assert.deepEqual(window.procedure.body, info.body);
    assert.ok(window.instructions.length > 0);
    facts[key] = {
      address,
      total_bytes: Number(body.total_bytes),
      instruction_count: window.instructions.length,
      pseudocode_nonempty: true,
      cli_mcp_observations_equal: true,
    };
  }
  // checkKey compares its key against 0x539 (1337); both call targets and the
  // branch resolve inside the imported pool.
  const checkKeyFacts = facts["checkKey"];
  assert.ok(
    checkKeyFacts.instruction_count >= 4,
    "checkKey's Dalvik bytecode window was incomplete",
  );

  // The DEX string pool is defined as string data by the packaged
  // preparation; loader-internal align markers stay out of the inventory.
  const secretPattern = "rea-dex-secret-42";
  const secretCli = await cliEvidence("search", secretPattern, [
    "--kind",
    "strings",
  ]);
  const secretHits = secretCli.normalized_result.filter(
    (item) => item.value === secretPattern,
  );
  assert.ok(
    secretHits.length === 1,
    `Pool value oracle missing: ${JSON.stringify(secretCli.normalized_result)}`,
  );
  const secret = secretHits[0];
  assert.match(secret.address, /^0x[0-9a-f]+$/u);
  const secretMemory = await call("read_bytes", {
    address: secret.address,
    length: secretPattern.length,
  });
  assert.equal(secretMemory.complete, true);
  assert.equal(
    hexBytes(secretMemory.bytes_hex),
    Buffer.from(secretPattern, "utf8").toString("hex"),
  );
  const searchMcp = await requireMcpOperationResult(
    await client.callTool({
      name: "search_strings",
      arguments: {
        pattern: secretPattern,
        mode: "literal",
        case_sensitive: true,
        document: documentName,
      },
    }),
    "search_strings",
  );
  assert.ok(
    searchMcp.some((item) => item.value === secretPattern),
    "MCP search missed the pool value oracle",
  );
  const inventoryMcp = await call("list_strings", { document: documentName });
  assert.ok(
    inventoryMcp.length >= 13,
    "String pool coverage was incomplete or the inventory drifted",
  );

  // Dalvik memory is loader-owned, but the .dex block maps the imported
  // file's bytes: reads return them, while no source mapping confesses a
  // file offset.
  const header = await call("read_bytes", { address: "0x0", length: 8 });
  assert.equal(header.complete, true);
  assert.equal(hexBytes(header.bytes_hex), "6465780a30333500");
  const cliHeader = await cliEvidence("read-bytes", "0x0", ["--length", "8"]);
  assert.deepEqual(cliHeader.normalized_result, header);
  const closed = await call("close_binary");
  opened = false;
  assert.equal((await call("binary_session")).open, false);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-dex",
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: {
      format: "dex",
      architecture: "dalvik",
      sha256,
      bytes: fixtureBytes.length,
    },
    profile: {
      digest: profile.digest,
      loader: profile.parameters.loader,
      language_id: profile.parameters.language_id,
      compiler_spec_id: profile.parameters.compiler_spec_id,
      dalvik_dex_version: profile.parameters.dalvik_dex_version,
    },
    transport: { cli: true, stdio_mcp: true },
    functions: facts,
    string_pool: {
      pool_value_verified: true,
      inventory_size: inventoryMcp.length,
    },
    memory_evidence: {
      dex_header_bytes_hex: hexBytes(header.bytes_hex),
      pool_bytes_verified: true,
      cli_mcp_parity: true,
    },
    original_unchanged: true,
    limitations: [
      "Read-only import evidence, not Android runtime execution or Java source recovery.",
      "The complete body is Ghidra's observed AddressSet, not independently proven historical dex ownership.",
      "Language/compiler identity comes from the DEX header version; the production authenticated bridge handshake rejects drift.",
      "Dalvik registers are not stack slots; decompiled output is operand-level instrumentation, not Java source recovery.",
      "Ghidra's DEX memory is loader-owned and publishes no file source mappings; byte reads return initialized bytes instead.",
    ],
  };
} catch (error) {
  if (stderr.trim())
    process.stderr.write(`DEX verifier MCP diagnostics:\n${stderr}\n`);
  throw error;
} finally {
  try {
    if (opened) {
      try {
        await call("close_binary");
      } catch (error) {
        process.stderr.write(`DEX cleanup close failed: ${String(error)}\n`);
      }
    }
    try {
      await client.close();
    } finally {
      await transport.close();
    }
    assert.equal(
      createHash("sha256")
        .update(await readFile(targetPath))
        .digest("hex"),
      sha256,
      "Original changed during cleanup",
    );
    const leftovers = (await readdir(runtime)).filter((name) =>
      name.startsWith("rea-ghidra-"),
    );
    assert.deepEqual(leftovers, [], "Owned Ghidra runtime survived close");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
assert.ok(report, "No DEX proof report was produced");
const verifierRun = await completeVerifierRun(run);
if (verifierRun.process_lineage.status === "verified")
  assert.deepEqual(
    verifierRun.process_lineage.descendants,
    [],
    "Owned descendants survived verifier cleanup",
  );
process.stdout.write(
  `${JSON.stringify({ verifier_run: verifierRun, ...report, cleanup: "complete" })}\n`,
);

function addressTo(address, delta) {
  if (typeof address !== "string" || !address.startsWith("0x"))
    throw new Error(`Unsupported DEX address ${address}`);
  return `0x${(BigInt(address) + delta).toString(16)}`;
}
async function call(name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent, `${name} omitted structured result`);
  return requireMcpOperationResult(result, name);
}
async function evidenceCall(name, arguments_) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  profileAssertions(evidence.analysis_profile);
  return evidence;
}
async function cliEvidence(command, argument, options = []) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      targetPath,
      ...(argument === undefined || argument === "" ? [] : [argument]),
      ...options,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  profileAssertions(evidence.analysis_profile);
  assert.equal(
    createHash("sha256")
      .update(await readFile(targetPath))
      .digest("hex"),
    sha256,
  );
  return evidence;
}
