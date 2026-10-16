import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";

import { satisfies } from "semver";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import {
  RADARE2_DIALECT,
  radare2Dialect,
  RIZIN_DIALECT,
  type Radare2Dialect,
} from "./Radare2Dialect.js";
import { RADARE2_PROVIDER_IDENTITY } from "./Radare2Identity.js";
import type { Radare2Launcher } from "./Radare2Pipe.js";
import { parseRadare2VersionBanner } from "./Radare2Values.js";

const VERSION_PROBE_TIMEOUT_MS = 15_000;
const VERSION_PROBE_OUTPUT_BYTES = 64 * 1024;

/** Actionable setup guidance shared by discovery, profiles and doctor. */
export const RADARE2_REQUIREMENT = `Set REA_RADARE2_PATH to the absolute path of a radare2 ${RADARE2_DIALECT.supportedRange} executable (verified with ${RADARE2_DIALECT.verifiedVersion}) or a Rizin ${RIZIN_DIALECT.supportedRange} executable (verified with ${RIZIN_DIALECT.verifiedVersion}); REA+ installs neither. See docs/radare2-provider.md.`;

/** One supported radare2 or Rizin executable observed through `-v`. */
export interface Radare2Engine {
  readonly executable: string;
  readonly dialect: Radare2Dialect;
  readonly version: string;
  readonly commit: string | null;
}

/** Resolve the configured executable and admit only a supported radare2 6.x or Rizin 0.9.x engine. */
export const probeRadare2Engine = async (
  configured: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  options: {
    readonly signal?: AbortSignal;
    readonly launcher?: Radare2Launcher;
  } = {},
): Promise<Result<Radare2Engine, AnalysisError>> => {
  let executable: string;
  try {
    executable = realpathSync(configured);
  } catch (cause: unknown) {
    return err(
      new ConfigurationError("REA_RADARE2_PATH cannot be resolved", {
        cause,
        settings: [
          { setting: "REA_RADARE2_PATH", constraint: RADARE2_REQUIREMENT },
        ],
      }),
    );
  }
  let banner: ReturnType<typeof parseRadare2VersionBanner>;
  try {
    const snapshot = await runOwnedCommand(
      {
        command: executable,
        arguments: ["-v"],
        runId: randomUUID(),
        hostEnvironment: { ...environment },
      },
      {
        timeoutMs: VERSION_PROBE_TIMEOUT_MS,
        diagnosticBytes: VERSION_PROBE_OUTPUT_BYTES,
      },
      {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.launcher === undefined
          ? {}
          : { launcher: options.launcher }),
      },
    );
    banner = parseRadare2VersionBanner(snapshot.stdout.text);
  } catch (cause: unknown) {
    if (cause instanceof OwnedCommandFailure && cause.reason === "cancelled")
      return err(new AnalysisCancelledError("radare2:profile", { cause }));
    return err(
      unavailable(
        `radare2 version probe failed: ${cause instanceof Error ? cause.message : "unknown failure"}`,
        cause,
      ),
    );
  }
  if (banner === null)
    return err(
      unavailable(
        "REA_RADARE2_PATH did not print a radare2 or Rizin version banner for -v.",
      ),
    );
  const dialect = radare2Dialect(banner.engine);
  if (!satisfies(banner.version, dialect.supportedRange))
    return err(
      unavailable(
        `${banner.engine} ${banner.version} is outside the supported ${dialect.supportedRange} release line.`,
      ),
    );
  return ok({
    executable,
    dialect,
    version: banner.version,
    commit: banner.commit,
  });
};

const unavailable = (reason: string, cause?: unknown) =>
  new AnalysisCapabilityUnavailableError(
    RADARE2_PROVIDER_IDENTITY.id,
    "open_binary",
    reason,
    {
      userMessage: RADARE2_REQUIREMENT,
      ...(cause === undefined ? {} : { cause }),
    },
  );
