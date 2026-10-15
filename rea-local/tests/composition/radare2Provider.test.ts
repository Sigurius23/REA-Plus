import { describe, expect, it } from "vitest";

import { parseConfig } from "../../src/config/parseConfig.js";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import { RADARE2_OPERATIONS } from "../../src/radare2/Radare2Identity.js";
import { Radare2Provider } from "../../src/radare2/Radare2Provider.js";

const provider = (environment: Readonly<Record<string, string>>) => {
  const config = parseConfig(environment);
  if (!config.ok) throw config.error;
  return new Radare2Provider(config.value, {});
};

const elf: BinaryTarget = {
  path: "/fixtures/fixture.elf",
  sha256: "0".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};

describe("radare2 provider discovery", () => {
  it("stays unconfigured, and out of automatic selection, until REA_RADARE2_PATH is set", () => {
    const unconfigured = provider({});
    expect(unconfigured.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "not_configured",
      reason: expect.stringContaining("REA_RADARE2_PATH"),
    });
    expect(unconfigured.capabilities()).toHaveLength(RADARE2_OPERATIONS.length);
    expect(
      unconfigured.capabilities().every(({ available }) => !available),
    ).toBe(true);

    expect(
      provider({
        REA_RADARE2_PATH: "/nonexistent/radare2",
      }).inspectAvailability(),
    ).toMatchObject({ status: "unavailable", code: "executable_missing" });

    const configured = provider({
      REA_RADARE2_PATH: process.execPath,
      REA_RADARE2_ANALYSIS: "aaaa",
    });
    expect(configured.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: { analysis_level: "aaaa", version_probed: false },
    });
    expect(configured.capabilities()[0]).toMatchObject({
      available: true,
      cachePolicy: "snapshot",
      effects: {
        mutatesArtifact: false,
        launchesProcess: true,
        mayAccessNetwork: false,
        mayShowUi: false,
      },
    });
  });

  it("admits native executables and refuses targets radare2 would misrepresent", () => {
    const radare2 = provider({ REA_RADARE2_PATH: process.execPath });
    expect(radare2.inspectTargetSupport(elf).status).toBe("supported");
    expect(
      radare2.inspectTargetSupport({
        ...elf,
        format: "pe",
        executableRole: "application",
        managed: true,
      }),
    ).toMatchObject({ code: "managed_target_unsupported" });
    expect(
      radare2.inspectTargetSupport({
        ...elf,
        format: "pe",
        executableRole: "non-executable",
        managed: false,
      }),
    ).toMatchObject({ code: "target_role_unsupported" });
    expect(
      radare2.inspectTargetSupport({
        ...elf,
        format: "mach-o",
        architecture: "arm64",
        availableArchitectures: ["arm64", "x86_64"],
      }),
    ).toMatchObject({ code: "architecture_unsupported" });
    expect(
      radare2.inspectTargetSupport({ ...elf, format: "dos-com" }),
    ).toMatchObject({ code: "target_format_unsupported" });
    expect(
      radare2.inspectTargetSupport({
        path: "/fixtures/app.apk",
        sha256: "0".repeat(64),
        kind: "archive",
        format: "apk",
      }),
    ).toMatchObject({ code: "target_kind_unsupported" });
  });
});
