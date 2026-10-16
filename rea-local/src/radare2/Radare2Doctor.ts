import { isAbsolute } from "node:path";

import type { DoctorProviderInspection } from "../application/Doctor.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { probeRadare2Engine, RADARE2_REQUIREMENT } from "./Radare2Version.js";

/**
 * Check the configured radare2 or Rizin executable for `rea doctor`. Only `-v` runs;
 * no target is copied or analyzed.
 */
export const inspectRadare2Executable = async (
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<DoctorProviderInspection> => {
  const configured = environment.REA_RADARE2_PATH;
  if (configured === undefined || configured.length === 0)
    return unavailable(false, {
      code: "not_configured",
      detail:
        "REA_RADARE2_PATH is not set; radare2 stays out of provider selection.",
      classification: "missing_analysis_engine",
    });
  if (!isAbsolute(configured))
    return unavailable(true, {
      code: "invalid_configuration",
      detail: "REA_RADARE2_PATH must be an absolute path.",
      classification: "config_drift",
    });
  const probed = await probeRadare2Engine(configured, environment);
  if (!probed.ok)
    return unavailable(true, {
      code: /is outside the supported/u.test(probed.error.message)
        ? "unsupported_version"
        : "executable_missing",
      detail:
        probed.error instanceof AnalysisCapabilityUnavailableError
          ? probed.error.reason
          : probed.error.message,
      classification: "missing_analysis_engine",
    });
  const { dialect, version, commit, executable } = probed.value;
  return {
    id: "radare2",
    configured: true,
    available: true,
    providerVersion: version,
    registrationEnvironment: { REA_RADARE2_PATH: configured },
    checks: [
      {
        name: "engine",
        ok: true,
        code: null,
        detail: `${dialect.engine} ${version}${commit === null ? "" : ` (${commit.slice(0, 12)})`} at ${executable}. Its pipe session and analysis start when a target is opened.`,
        remediation: null,
        classification: "missing_analysis_engine",
      },
    ],
  };
};

const unavailable = (
  configured: boolean,
  failure: {
    readonly code: string;
    readonly detail: string;
    readonly classification: "missing_analysis_engine" | "config_drift";
  },
): DoctorProviderInspection => ({
  id: "radare2",
  configured,
  available: false,
  providerVersion: null,
  registrationEnvironment: {},
  checks: [
    {
      name: "engine",
      ok: false,
      code: failure.code,
      detail: failure.detail,
      remediation: RADARE2_REQUIREMENT,
      classification: failure.classification,
    },
  ],
});
