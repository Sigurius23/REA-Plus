import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import { silentLogger } from "../logger.js";
import { hopperLoaderArgsForTarget } from "./HopperAnalysisProfile.js";
import { HopperProvider } from "./HopperProvider.js";

describe("Hopper provider capabilities", () => {
  it("declines Android DEX targets and builds no loader arguments for them", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger, {});
    const dex = {
      path: "/tmp/classes.dex",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "dex",
      architecture: "dalvik",
      availableArchitectures: ["dalvik"],
      dex: { version: "039" },
    } as const;
    expect(provider.inspectTargetSupport(dex)).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
    expect(hopperLoaderArgsForTarget(dex).ok).toBe(false);
  });

  it("declines DOS MZ targets with a provider-specific support reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/legacy.exe",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
});
