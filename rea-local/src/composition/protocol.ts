import { ProtocolFieldsService } from "../application/protocol/ProtocolFieldsService.js";
import { createProtocolFieldsInspector } from "../protocol/ProtocolFieldsInspector.js";

/** Compose offline protocol field inference; it needs no tools or configuration. */
export const createProtocolFieldsService = (): ProtocolFieldsService =>
  new ProtocolFieldsService(createProtocolFieldsInspector());
