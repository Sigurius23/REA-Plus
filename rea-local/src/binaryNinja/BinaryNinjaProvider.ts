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
import {
  readExternalMcpConfiguration,
  type ExternalMcpRegistration,
} from "../externalMcp/ExternalMcpConfiguration.js";
import {
  createExternalMcpConnection,
  type ExternalMcpConnectionFactory,
} from "../externalMcp/ExternalMcpConnection.js";
import {
  BINARY_NINJA_LIMITATIONS,
  BINARY_NINJA_OPERATIONS,
  BINARY_NINJA_PROVIDER_IDENTITY,
} from "./BinaryNinjaIdentity.js";
import { BinaryNinjaAnalysisClient } from "./BinaryNinjaAnalysisClient.js";
import { missingBinaryNinjaToolRoles } from "./BinaryNinjaMcpArguments.js";

/** Caller-supplied official Binary Ninja MCP candidate; discovery starts no process. */
export class BinaryNinjaProvider implements AnalysisProviderCandidate {
  #registration:
    | Result<ExternalMcpRegistration, ConfigurationError>
    | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly connectionFactory: ExternalMcpConnectionFactory = createExternalMcpConnection,
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity() {
    return BINARY_NINJA_PROVIDER_IDENTITY;
  }

  capabilities() {
    const registration = this.#registrationResult();
    const enabled =
      registration.ok &&
      missingBinaryNinjaToolRoles(registration.value.allowedTools ?? [])
        .length === 0;
    return BINARY_NINJA_OPERATIONS.map((operation) => ({
      provider: BINARY_NINJA_PROVIDER_IDENTITY,
      operation,
      cachePolicy: "live" as const,
      effects: {
        mutatesArtifact: false,
        launchesProcess: registration.ok && registration.value.type === "stdio",
        mayShowUi: registration.ok && registration.value.type === "http",
        mayAccessNetwork: registration.ok && registration.value.type === "http",
        mayWriteFilesystem:
          registration.ok && registration.value.type === "stdio",
        changesPermissions: false,
        requiresRoot: false,
      },
      ...(enabled
        ? { available: true as const, reason: null }
        : {
            available: false as const,
            reason: registration.ok
              ? `Binary Ninja server allowlist is missing normalized roles: ${missingBinaryNinjaToolRoles(registration.value.allowedTools ?? []).join(", ")}.`
              : registration.error.message,
            availabilityCode: registration.ok
              ? ("open_options_invalid" as const)
              : this.config.externalMcpConfigPath === undefined
                ? ("not_configured" as const)
                : ("open_options_invalid" as const),
          }),
      limitations: BINARY_NINJA_LIMITATIONS,
    }));
  }

  inspectAvailability(): ProviderAvailability {
    const registration = this.#registrationResult();
    if (!registration.ok)
      return {
        status: "unavailable",
        code:
          this.config.externalMcpConfigPath === undefined
            ? "not_configured"
            : "open_options_invalid",
        reason: registration.error.message,
        diagnostics: {
          configured: this.config.externalMcpConfigPath !== undefined,
          server_id: "binary-ninja",
          live_connection_probed: false,
        },
      };
    const missingRoles = missingBinaryNinjaToolRoles(
      registration.value.allowedTools ?? [],
    );
    if (missingRoles.length > 0)
      return {
        status: "unavailable",
        code: "open_options_invalid",
        reason: `The binary-ninja.allowedTools list is missing official tool roles: ${missingRoles.join(", ")}.`,
        diagnostics: {
          configured: true,
          server_id: "binary-ninja",
          transport: registration.value.type,
          live_connection_probed: false,
          missing_tool_roles: [...missingRoles],
          detected_allowlist: [...(registration.value.allowedTools ?? [])],
        },
      };
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        configured: true,
        server_id: "binary-ninja",
        transport: registration.value.type,
        live_connection_probed: false,
        exact_tool_catalog_verified: false,
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
          "The normalized Binary Ninja adapter admits executable inputs only. Binary Ninja databases and non-executable artifacts remain available through caller-configured generic MCP passthrough.",
        diagnostics,
      };
    if (target.format === "pe" && target.executableRole === "non-executable")
      return {
        status: "unsupported",
        code: "target_role_unsupported",
        reason:
          "The normalized Binary Ninja adapter accepts executable PE images, not PE files explicitly classified as non-executable.",
        diagnostics,
      };
    if (target.format === "dex")
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          "Binary Ninja does not analyze Android DEX bytecode without a plugin. Select the radare2 or Ghidra provider instead.",
        diagnostics,
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError("binary-ninja:profile"));
    const registration = this.#registrationResult();
    if (!registration.ok) return registration;
    return ok({
      profile: createAnalysisProfile(BINARY_NINJA_PROVIDER_IDENTITY, {
        version_scope: "rea-binary-ninja-official-mcp-adapter",
        upstream_distribution_version: null,
        engine_version: null,
        mcp_server_id: "binary-ninja",
        transport: registration.value.type,
        allowed_tools: [...(registration.value.allowedTools ?? [])],
        registration_digest: createHash("sha256")
          .update(canonicalize(registration.value) ?? "")
          .digest("hex"),
        cache_policy: "live",
      }),
    });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const registration = this.#registrationResult();
    if (!registration.ok)
      return {
        execute: async () => err(registration.error),
        close: async () => ok(null),
      };
    const connection = this.connectionFactory(
      registration.value,
      this.environment,
    );
    return new BinaryNinjaAnalysisClient(
      target,
      connection,
      registration.value.allowedTools ?? [],
      profile,
    );
  }

  #registrationResult(): Result<ExternalMcpRegistration, ConfigurationError> {
    this.#registration ??= this.#readRegistration();
    return this.#registration;
  }

  #readRegistration(): Result<ExternalMcpRegistration, ConfigurationError> {
    const loaded = readExternalMcpConfiguration(
      this.config.externalMcpConfigPath,
    );
    if (!loaded.ok) return loaded;
    const registration = loaded.value.mcpServers["binary-ninja"];
    if (registration === undefined)
      return err(
        new ConfigurationError("Binary Ninja MCP is not configured", {
          settings: [
            {
              setting: "REA_EXTERNAL_MCP_CONFIG",
              constraint:
                'Add a caller-supplied "binary-ninja" server registration with an explicit allowedTools list; see docs/binary-ninja-provider.md.',
            },
          ],
        }),
      );
    return ok(registration);
  }
}
