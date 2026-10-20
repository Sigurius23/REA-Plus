import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

import type {
  AnalysisClient,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  ProviderAvailability,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";
import type { AppConfig } from "../config/types.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { privateRuntimeRootCapability } from "../process/PrivateRuntimeRoot.js";
import {
  readOfficialIdaConfiguration,
  type IdaConfiguration,
} from "./IdaConfiguration.js";
import {
  createIdaMcpConnection,
  type IdaMcpConnection,
} from "./IdaMcpConnection.js";
import { OfficialIdaMcpConnection } from "./OfficialIdaMcpConnection.js";
import { IdaSessionClient } from "./IdaSessionClient.js";
import {
  IDA_OFFICIAL_LIMITATIONS,
  IDA_OFFICIAL_PROVIDER_IDENTITY,
  idaCapabilities,
} from "./IdaProviderCapabilities.js";

/** Bring-your-own Hex-Rays IDA MCP candidate; discovery starts no upstream process. */
export class OfficialIdaProvider implements AnalysisProviderCandidate {
  #registration: Result<IdaConfiguration, ConfigurationError> | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly connectionFactory: (
      config: IdaConfiguration,
      environment: Readonly<NodeJS.ProcessEnv>,
    ) => IdaMcpConnection = createIdaMcpConnection,
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity() {
    return IDA_OFFICIAL_PROVIDER_IDENTITY;
  }

  capabilities() {
    const configuration = this.#configuration();
    return idaCapabilities(
      "headless",
      configuration.ok && "command" in configuration.value,
      IDA_OFFICIAL_PROVIDER_IDENTITY,
      IDA_OFFICIAL_LIMITATIONS,
      true,
    );
  }

  inspectAvailability(): ProviderAvailability {
    const configuration = this.#configuration();
    if (!configuration.ok)
      return {
        status: "unavailable",
        code:
          this.config.idaOfficialMcpConfigPath === undefined
            ? "not_configured"
            : "open_options_invalid",
        reason: configuration.error.message,
        diagnostics: {
          configured: this.config.idaOfficialMcpConfigPath !== undefined,
          mode: "headless",
          live_connection_probed: false,
        },
      };
    const privacy = privateRuntimeRootCapability();
    return privacy.available
      ? {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {
            configured: true,
            mode: "headless-private-copy",
            transport: "command" in configuration.value ? "stdio" : "http",
            live_connection_probed: false,
            user_database_mutation: false,
          },
        }
      : {
          status: "unavailable",
          code: "unsupported_host",
          reason: privacy.reason,
          diagnostics: {
            configured: true,
            mode: "headless-private-copy",
            live_connection_probed: false,
            private_workspace_available: false,
          },
        };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason:
          "The normalized official IDA provider admits executable inputs only; analysis databases and other artifacts remain available through the caller-configured MCP bridge.",
        diagnostics,
      };
    if (target.architecture === "mips")
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "The normalized official IDA adapter has no verified MIPS lane; select a supported Ghidra profile instead.",
        diagnostics,
      };
    if (target.format === "dex")
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          "The normalized official IDA adapter has no verified DEX lane; select the radare2 or Ghidra provider instead.",
        diagnostics,
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError("ida-official:profile"));
    const configuration = this.#configuration();
    if (!configuration.ok) return configuration;
    return ok({
      profile: createAnalysisProfile(IDA_OFFICIAL_PROVIDER_IDENTITY, {
        version_scope: "rea-ida-official-adapter",
        engine_version: null,
        upstream_distribution_version: null,
        mode: "headless-private-copy",
        compatibility_profile: "hexrays-ida-mcp-python-readonly-1",
        database_revision: null,
        cache_policy: "live",
        registration_digest: createHash("sha256")
          .update(canonicalize(configuration.value) ?? "")
          .digest("hex"),
      }),
    });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const configuration = this.#configuration();
    if (!configuration.ok)
      return {
        execute: async () => err(configuration.error),
        close: async () => ok(null),
      };
    const upstream = this.connectionFactory(
      configuration.value,
      this.environment,
    );
    const connection = new OfficialIdaMcpConnection(
      upstream,
      configuration.value,
    );
    return new IdaSessionClient(
      configuration.value,
      target,
      connection,
      profile,
      {
        provider: IDA_OFFICIAL_PROVIDER_IDENTITY,
        limitations: IDA_OFFICIAL_LIMITATIONS,
        protocol: "legacy",
        requireActiveLease: false,
      },
    );
  }

  #configuration() {
    this.#registration ??=
      this.config.idaOfficialMcpConfigPath === undefined
        ? err(
            new ConfigurationError(
              "Official Hex-Rays IDA MCP is not configured",
              {
                settings: [
                  {
                    setting: "REA_IDA_OFFICIAL_MCP_CONFIG",
                    constraint:
                      "Set REA_IDA_OFFICIAL_MCP_CONFIG to a caller-supplied Hex-Rays IDA MCP registration; see docs/ida-provider.md.",
                  },
                ],
              },
            ),
          )
        : readOfficialIdaConfiguration(this.config.idaOfficialMcpConfigPath);
    return this.#registration;
  }
}
