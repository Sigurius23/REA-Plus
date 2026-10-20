import { CoverageLogService } from "../application/drcov/CoverageLogService.js";
import { CoverageLogReader } from "../drcov/CoverageLogReader.js";

/** Compose the offline coverage reader; it needs no tools or configuration. */
export const createCoverageLogService = (): CoverageLogService =>
  new CoverageLogService(new CoverageLogReader());
