import { LogicCaptureService } from "../application/logic/LogicCaptureService.js";
import { LogicCaptureInspector } from "../logic/LogicCaptureInspector.js";

/** Compose the session reader; sigrok-cli is resolved only when decoding. */
export const createLogicCaptureService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): LogicCaptureService =>
  new LogicCaptureService(new LogicCaptureInspector(environment));
