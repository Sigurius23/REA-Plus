import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { BytePatternService } from "../application/patterns/BytePatternService.js";
import type { CheatTableService } from "../application/patterns/CheatTableService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named byte-pattern and cheat-table contracts to shared validation and Evidence recording. */
export const registerPatternTools = (
  server: EvidenceMcpServer,
  services: {
    readonly patterns: BytePatternService;
    readonly tables: CheatTableService;
  },
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const bind = (
    name: "scan_byte_patterns" | "inspect_cheat_table",
    run: Parameters<typeof createEvidenceToolHandler>[1],
  ) => {
    const contract = toolContract(name);
    const handler = createEvidenceToolHandler(
      server,
      run,
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
  bind("scan_byte_patterns", (input, options) =>
    services.patterns.scan(input, options),
  );
  bind("inspect_cheat_table", (input, options) =>
    services.tables.inspect(input, options),
  );
};
