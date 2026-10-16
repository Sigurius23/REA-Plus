import { accessSync, constants, statSync } from "node:fs";

import type {
  AnalysisClient,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import {
  DEFAULT_RADARE2_ANALYSIS_TIMEOUT_MS,
  type Radare2AnalysisLevel,
} from "../config/radare2Settings.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { Radare2AnalysisClient } from "./Radare2AnalysisClient.js";
import {
  RADARE2_CAPABILITY_LIMITATIONS,
  RADARE2_OPERATIONS,
  RADARE2_PROVIDER_IDENTITY,
} from "./Radare2Identity.js";
import type { Radare2Launcher } from "./Radare2Pipe.js";
import {
  probeRadare2Engine,
  RADARE2_REQUIREMENT as REQUIREMENT,
  type Radare2Engine,
} from "./Radare2Version.js";

/** Injectable process seams for deterministic boundary tests. */
export interface Radare2ProviderSeams {
  readonly launcher?: Radare2Launcher;
  readonly runtimeParent?: string;
}

/** Caller-supplied radare2 (or Rizin) deep provider; discovery starts no process. */
export class Radare2Provider implements AnalysisProviderCandidate {
  private readonly environment: NodeJS.ProcessEnv;
  readonly #resolved = new Map<string, Radare2Engine>();

  constructor(
    private readonly config: AppConfig,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly seams: Radare2ProviderSeams = {},
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity() {
    return RADARE2_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    const availability = this.inspectAvailability();
    return RADARE2_OPERATIONS.map((operation) => ({
      provider: RADARE2_PROVIDER_IDENTITY,
      operation,
      // Results are immutable for one profile: fixed engine version, analysis
      // level and process arguments over SHA-256-identified bytes.
      cachePolicy: "snapshot" as const,
      effects: {
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: true,
        changesPermissions: false,
        requiresRoot: false,
      },
      ...(availability.status === "available"
        ? { available: true as const, reason: null }
        : {
            available: false as const,
            reason: availability.reason,
            availabilityCode: availability.code,
          }),
      limitations: RADARE2_CAPABILITY_LIMITATIONS,
    }));
  }

  inspectAvailability(): ProviderAvailability {
    const configured = this.config.radare2Path;
    if (configured === undefined)
      return {
        status: "unavailable",
        code: "not_configured",
        reason: REQUIREMENT,
        diagnostics: { configured: false },
      };
    try {
      if (!statSync(configured).isFile()) throw new Error("not a regular file");
      accessSync(configured, constants.X_OK);
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason: `REA_RADARE2_PATH is not an executable file: ${configured}`,
        diagnostics: {
          configured: true,
          executable: configured,
          error: cause instanceof Error ? cause.message : "inaccessible",
        },
      };
    }
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        configured: true,
        executable: configured,
        analysis_level: this.#analysisLevel(),
        version_probed: false,
      },
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.kind === "executable" ? target.architecture : null,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason:
          "The radare2 adapter analyzes executable images; archives, databases and other artifacts use REA+'s artifact tools.",
        diagnostics,
      };
    if (target.format === "dos-com")
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          "DOS COM images carry no header radare2 can load with a verified entry context; use Ghidra's COM profile.",
        diagnostics,
      };
    if (target.format === "pe" && target.executableRole === "non-executable")
      return {
        status: "unsupported",
        code: "target_role_unsupported",
        reason:
          "The radare2 adapter accepts executable PE images, not PE files classified as non-executable.",
        diagnostics,
      };
    if (target.format === "pe" && target.managed)
      return {
        status: "unsupported",
        code: "managed_target_unsupported",
        reason:
          "radare2 sees only the native stub of a CLI image; use REA+'s managed-code tools for its metadata and IL.",
        diagnostics,
      };
    if (target.format === "mach-o" && target.availableArchitectures.length > 1)
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "The radare2 adapter does not yet bind one slice of a universal Mach-O; extract the selected slice first.",
        diagnostics: {
          ...diagnostics,
          available_architectures: [...target.availableArchitectures],
        },
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<
    Result<{ readonly profile: AnalysisProfileCommitment }, AnalysisError>
  > {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError("radare2:profile"));
    const configured = this.config.radare2Path;
    if (configured === undefined)
      return err(
        new ConfigurationError("radare2 is not configured", {
          settings: [{ setting: "REA_RADARE2_PATH", constraint: REQUIREMENT }],
        }),
      );
    const probed = await probeRadare2Engine(configured, this.environment, {
      ...(options?.signal === undefined ? {} : { signal: options.signal }),
      ...(this.seams.launcher === undefined
        ? {}
        : { launcher: this.seams.launcher }),
    });
    if (!probed.ok) return probed;
    const { dialect, version, commit } = probed.value;
    const profile = createAnalysisProfile(RADARE2_PROVIDER_IDENTITY, {
      version_scope: "rea-radare2-pipe-adapter",
      engine: dialect.engine,
      engine_version: version,
      engine_commit: commit,
      analysis_level: this.#analysisLevel(),
      process_arguments: [...dialect.processArguments],
      cache_policy: "snapshot",
    });
    this.#resolved.set(profile.digest, probed.value);
    return ok({ profile });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const resolved =
      profile === undefined ? undefined : this.#resolved.get(profile.digest);
    if (resolved === undefined)
      return {
        execute: async (operation) =>
          err(
            new AnalysisCapabilityUnavailableError(
              RADARE2_PROVIDER_IDENTITY.id,
              operation,
              "The radare2 client requires a profile resolved by this provider.",
              { userMessage: REQUIREMENT },
            ),
          ),
        close: async () => ok(null),
      };
    return new Radare2AnalysisClient(
      target,
      {
        executable: resolved.executable,
        dialect: resolved.dialect,
        engineVersion: resolved.version,
        analysisLevel: this.#analysisLevel(),
        analysisTimeoutMs:
          this.config.radare2AnalysisTimeoutMs ??
          DEFAULT_RADARE2_ANALYSIS_TIMEOUT_MS,
        environment: this.environment,
        ...(this.seams.launcher === undefined
          ? {}
          : { launcher: this.seams.launcher }),
        ...(this.seams.runtimeParent === undefined
          ? {}
          : { runtimeParent: this.seams.runtimeParent }),
      },
      profile,
    );
  }

  #analysisLevel(): Radare2AnalysisLevel {
    return this.config.radare2AnalysisLevel ?? "aaa";
  }
}
