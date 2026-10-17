import { LibraryIdentificationService } from "../application/libid/LibraryIdentificationService.js";
import { LibraryIdentifier } from "../libid/LibraryIdentifier.js";

/** Compose offline library identification; it needs no tools or configuration. */
export const createLibraryIdentificationService =
  (): LibraryIdentificationService =>
    new LibraryIdentificationService(new LibraryIdentifier());
