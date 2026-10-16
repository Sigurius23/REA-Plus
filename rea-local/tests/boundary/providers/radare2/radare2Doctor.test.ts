import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { inspectRadare2Executable } from "../../../../src/radare2/Radare2Doctor.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const fakeEngine = async (version: string): Promise<string> => {
  const root = await createTestTempDirectory("rea-radare2-doctor-");
  const path = join(root, "radare2");
  await writeFile(
    path,
    `#!/bin/sh\nprintf 'radare2 ${version} +1 abi:152 @ linux-x86_64\\ncommit: 485e5e205b190fc297a2a95a6f982ff5d9f54039\\n'\n`,
  );
  await chmod(path, 0o755);
  return path;
};

describe("radare2 doctor inspection", () => {
  it("reports an unconfigured engine without running anything", async () => {
    expect(await inspectRadare2Executable({})).toMatchObject({
      id: "radare2",
      configured: false,
      available: false,
      registrationEnvironment: {},
      checks: [{ name: "engine", ok: false, code: "not_configured" }],
    });
    expect(
      await inspectRadare2Executable({ REA_RADARE2_PATH: "radare2" }),
    ).toMatchObject({
      checks: [
        { code: "invalid_configuration", classification: "config_drift" },
      ],
    });
  });

  it("rejects an executable that is not radare2", async () => {
    expect(
      await inspectRadare2Executable({ REA_RADARE2_PATH: process.execPath }),
    ).toMatchObject({
      configured: true,
      available: false,
      checks: [
        {
          code: "executable_missing",
          detail: expect.stringContaining(
            "did not print a radare2 or Rizin version",
          ),
        },
      ],
    });
  });

  it.skipIf(process.platform === "win32")(
    "admits a supported engine and carries its path into client registrations",
    async () => {
      const path = await fakeEngine("6.2.4");
      expect(
        await inspectRadare2Executable({ REA_RADARE2_PATH: path }),
      ).toMatchObject({
        available: true,
        providerVersion: "6.2.4",
        registrationEnvironment: { REA_RADARE2_PATH: path },
        checks: [
          { ok: true, detail: expect.stringContaining("radare2 6.2.4") },
        ],
      });
      expect(
        await inspectRadare2Executable({
          REA_RADARE2_PATH: await fakeEngine("5.9.8"),
        }),
      ).toMatchObject({
        available: false,
        checks: [{ code: "unsupported_version" }],
      });
    },
  );
});
