import { EXTERNAL_MCP_TOOL_CONTRACTS } from "../contracts/externalMcp/externalMcpToolContracts.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { ExternalMcpAnalysisService } from "../externalMcp/ExternalMcpAnalysisService.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Register the opt-in generic external MCP bridge through canonical contracts. */
export const registerExternalMcpTools = (
  server: EvidenceMcpServer,
  service: ExternalMcpAnalysisService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of EXTERNAL_MCP_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
