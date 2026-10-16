import { GodotFileService } from "../application/godot/GodotFileService.js";
import { GodotFileInspector } from "../godot/GodotInspector.js";

/** Compose the offline Godot file reader; keys for encrypted files are read from the named environment variables. */
export const createGodotFileService = (
  environment: Readonly<Record<string, string | undefined>> = {},
): GodotFileService =>
  new GodotFileService(new GodotFileInspector(environment));
