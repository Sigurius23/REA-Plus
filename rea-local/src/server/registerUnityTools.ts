import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { UnityAssetsService } from "../application/unity/UnityAssetsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named Unity asset contract to shared validation and session Evidence recording. */
export const registerUnityTools = (
  server: EvidenceMcpServer,
  service: UnityAssetsService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("inspect_unity_assets");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.inspect(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
