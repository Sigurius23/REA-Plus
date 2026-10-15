import type { ExternalMcpConfiguration } from "../externalMcp/ExternalMcpConfiguration.js";
import type { ExternalMcpConnectionFactory } from "../externalMcp/ExternalMcpConnection.js";
import { ExternalMcpProvider } from "../externalMcp/ExternalMcpProvider.js";

/** Compose the generic MCP client with the caller-selected environment. */
export const createExternalMcpProvider = (
  configuration: ExternalMcpConfiguration,
  environment: Readonly<NodeJS.ProcessEnv>,
  connectionFactory?: ExternalMcpConnectionFactory,
): ExternalMcpProvider =>
  new ExternalMcpProvider(configuration, environment, connectionFactory);
