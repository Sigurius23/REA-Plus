import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { MobileRuntimeAnalysisService } from "../application/mobileRuntime/MobileRuntimeAnalysisService.js";
import { MOBILE_RUNTIME_TOOL_CONTRACTS } from "../contracts/mobileRuntime/mobileRuntimeToolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Register explicit Frida/Objection runtime operations via canonical contracts. */
export const registerMobileRuntimeTools = (
  server: EvidenceMcpServer,
  service: MobileRuntimeAnalysisService,
  logger: Logger,
  options: {
    readonly recordEvidence?: EvidenceWriter["recordEvidence"];
    readonly withAdmittedAnalysis?: WithAdmittedAnalysis;
  } = {},
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    options.recordEvidence,
    options.withAdmittedAnalysis,
  );
  for (const contract of MOBILE_RUNTIME_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
