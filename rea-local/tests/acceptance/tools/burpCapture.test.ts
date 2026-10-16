import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

import { BURP_CAPTURE_PROVIDER_IDENTITY } from "../../../src/browser/history/CaptureRelease.js";
import { createBurpExport } from "../../fixtures/burpExport.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const execute = promisify(execFile);
const cli = fileURLToPath(new URL("../../../scripts/rea.mjs", import.meta.url));

it("decodes a Burp Suite export through the CLI's owned decoder process", async () => {
  const root = await createTestTempDirectory("rea-burp-capture-");
  const path = join(root, "history.xml");
  await writeFile(path, createBurpExport());
  const { stdout } = await execute(
    process.execPath,
    [cli, "inspect-web-network-capture", path, "burp", "--json"],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  const evidence = JSON.parse(stdout);
  const capture = evidence.normalized_result;
  expect(capture.format).toBe("burp");
  expect(capture.decoder).toEqual(BURP_CAPTURE_PROVIDER_IDENTITY);
  expect(capture.total_records).toBe(4);
  expect(capture.records[0].reported.request).toMatchObject({
    method: "POST",
    url: "https://api.example.test/scores?season=3&mode=ranked",
  });
  expect(JSON.stringify(capture)).not.toContain("secret-token");
  expect(capture.limitations).toEqual(
    expect.arrayContaining([expect.stringContaining("Burp XML (via HAR)")]),
  );
}, 120_000);
