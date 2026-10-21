import { DataBlobService } from "../application/blob/DataBlobService.js";
import { createDataBlobInspector } from "../blob/BlobInspector.js";

/** Compose the offline data blob reader; it needs no tools or configuration. */
export const createDataBlobService = (): DataBlobService =>
  new DataBlobService(createDataBlobInspector());
