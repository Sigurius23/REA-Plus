import { BytePatternService } from "../application/patterns/BytePatternService.js";
import { CheatTableService } from "../application/patterns/CheatTableService.js";
import { CheatTableInspector } from "../patterns/CheatTableInspector.js";
import { PatternScanProvider } from "../patterns/PatternScanProvider.js";

/** Compose the offline AOB scanner; it needs no tools or configuration. */
export const createBytePatternService = (): BytePatternService =>
  new BytePatternService(new PatternScanProvider());

/** Compose the offline Cheat Engine table reader. */
export const createCheatTableService = (): CheatTableService =>
  new CheatTableService(new CheatTableInspector());
