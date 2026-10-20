import { readGodotPack, locateGodotPack } from "../gamearchives/GodotPck.js";
import { GameArchiveError } from "../gamearchives/GameArchiveTypes.js";
import type {
  GodotFileReport,
  InspectGodotFileInput,
} from "../domain/godot/godotFile.js";
import { GodotFormatError, GodotSelectionError } from "./GodotBytes.js";
import {
  decompressGodot,
  decryptGodot,
  passwordKey,
} from "./GodotContainers.js";

/**
 * The bytes to decode: the selected file, or one entry of a Godot pack
 * (following a .remap to the exported file), with GDEC encryption and GCPF
 * compression removed.
 */

export type Environment = Readonly<Record<string, string | undefined>>;

export interface SelectedBytes {
  readonly data: Buffer;
  readonly entry: GodotFileReport["entry"];
  readonly layers: GodotFileReport["layers"];
}

const MAX_LAYERS = 4;

const normalized = (path: string): string =>
  path.replace(/^res:\/\//u, "").replace(/^\/+/u, "");

/** Godot's .remap files are a [remap] section with path="res://...". */
const remapTarget = (text: string): string | null =>
  /^\s*path\s*=\s*"([^"]+)"/mu.exec(text)?.[1] ?? null;

const packEntry = (
  bytes: Buffer,
  wanted: string,
): { data: Buffer; entry: NonNullable<GodotFileReport["entry"]> } => {
  if (locateGodotPack(bytes) === null)
    throw new GodotSelectionError(
      "entry was given, but the file is not a Godot pack or an executable with one embedded.",
      "entry",
    );
  const listing = readGodotPack(bytes);
  const byPath = new Map(listing.entries.map((entry) => [entry.path, entry]));
  const read = (path: string) => {
    const entry = byPath.get(path);
    if (entry === undefined || entry.removed) return null;
    if (entry.encrypted)
      throw new GodotSelectionError(
        `Entry ${path} is encrypted with the game's key; REA+ does not decrypt pack entries.`,
        "entry",
      );
    const part = entry.parts[0];
    if (part?.kind !== "file") return null;
    return {
      path,
      offset: part.offset,
      data: bytes.subarray(part.offset, part.offset + part.length),
    };
  };
  const path = normalized(wanted);
  let found = read(path);
  let remappedFrom: string | null = null;
  if (found === null) {
    const remap = read(`${path}.remap`);
    const target =
      remap === null ? null : remapTarget(remap.data.toString("utf8"));
    if (target !== null) {
      found = read(normalized(target));
      remappedFrom = path;
    }
  }
  if (found === null)
    throw new GodotSelectionError(
      `The pack has no entry ${path} (nor ${path}.remap); inspect_game_archive lists its entries.`,
      "entry",
    );
  return {
    data: found.data,
    entry: {
      path: found.path,
      remapped_from: remappedFrom,
      offset: found.offset,
      bytes: found.data.length,
      pack_engine: listing.engineVersion,
    },
  };
};

const keyFor = (
  input: InspectGodotFileInput,
  environment: Environment,
): Buffer => {
  const field = input.key_env === undefined ? "password_env" : "key_env";
  const name = input.key_env ?? input.password_env;
  if (name === undefined)
    throw new GodotSelectionError(
      "The file is encrypted (GDEC). Name the environment variable holding its key with key_env, or its password with password_env.",
      "key_env",
    );
  const secret = environment[name];
  if (secret === undefined || secret === "")
    throw new GodotSelectionError(
      `Environment variable ${name} is not set.`,
      field,
    );
  if (field === "password_env") return passwordKey(secret);
  if (!/^[0-9a-fA-F]{64}$/u.test(secret.trim()))
    throw new GodotSelectionError(
      `Environment variable ${name} must hold 64 hexadecimal digits (a 32-byte AES-256 key).`,
      field,
    );
  return Buffer.from(secret.trim(), "hex");
};

const magic = (data: Buffer): string => data.subarray(0, 4).toString("latin1");

export const selectGodotBytes = (
  bytes: Buffer,
  input: InspectGodotFileInput,
  environment: Environment,
  maxOutput: number,
): SelectedBytes => {
  let data = bytes;
  let entry: GodotFileReport["entry"] = null;
  if (input.entry !== undefined) {
    try {
      ({ data, entry } = packEntry(bytes, input.entry));
    } catch (cause) {
      if (cause instanceof GameArchiveError)
        throw new GodotFormatError(
          `The pack cannot be read: ${cause.message}`,
          { cause },
        );
      throw cause;
    }
  }
  const layers: GodotFileReport["layers"][number][] = [];
  for (let step = 0; step < MAX_LAYERS; step += 1) {
    const before = data.length;
    if (magic(data) === "GDEC") {
      const field = input.key_env === undefined ? "password_env" : "key_env";
      const decrypted = decryptGodot(data, keyFor(input, environment));
      if (decrypted === null)
        throw new GodotSelectionError(
          "The key does not decrypt the file: the MD5 Godot stores with it does not match.",
          field,
        );
      data = decrypted.data;
      layers.push({
        kind: "decrypted",
        format: `GDEC (Godot ${String(decrypted.engine)})`,
        input_bytes: before,
        output_bytes: data.length,
      });
    } else if (magic(data) === "GCPF") {
      const { data: out, mode } = decompressGodot(data, maxOutput);
      data = out;
      layers.push({
        kind: "decompressed",
        format: `GCPF ${mode}`,
        input_bytes: before,
        output_bytes: data.length,
      });
    } else break;
  }
  return { data, entry, layers };
};
