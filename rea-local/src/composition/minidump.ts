import { MinidumpService } from "../application/minidump/MinidumpService.js";
import { MinidumpInspector } from "../minidump/MinidumpInspector.js";

/** Compose the offline minidump reader; it needs no tools or configuration. */
export const createMinidumpService = (): MinidumpService =>
  new MinidumpService(new MinidumpInspector());
