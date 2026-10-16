import { MobsfReportService } from "../application/mobsf/MobsfReportService.js";
import { MobsfInspector } from "../mobsf/MobsfInspector.js";

/** Compose the offline MobSF report reader; it needs no tools or configuration. */
export const createMobsfReportService = (): MobsfReportService =>
  new MobsfReportService(new MobsfInspector());
