import type { GameMakerDataReport } from "../domain/gamemaker/gameMakerData.js";
import type { Form } from "./GameMakerForm.js";

type General = NonNullable<GameMakerDataReport["general"]>;

const INFO_FLAGS: readonly (readonly [number, string])[] = [
  [0x1, "fullscreen"],
  [0x8, "interpolate"],
  [0x10, "scale"],
  [0x20, "show_cursor"],
  [0x40, "sizeable"],
  [0x80, "screen_key"],
  [0x1000, "steam_enabled"],
  [0x2000, "app_data_save_location"],
  [0x4000, "borderless_window"],
  [0x8000, "javascript_mode"],
  [0x10000, "run_from_ide"],
  [0x20000, "transparent_background"],
];

/** Chunks that first appear in a runtime, newest first (UndertaleModTool's detection). */
const VERSION_CHUNKS: readonly (readonly [string, string])[] = [
  ["UILR", "2024.13"],
  ["PSEM", "2023.2"],
  ["FEAT", "2022.8"],
  ["FEDS", "2.3.6"],
  ["SEQN", "2.3"],
  ["TGIN", "2.2.1"],
];

const builtAt = (seconds: bigint): string | null => {
  const milliseconds = Number(seconds) * 1000;
  if (seconds === 0n || !Number.isFinite(milliseconds)) return null;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

/** Read GEN8: identity, stored version, window, flags, timestamp and room order. */
export const readGeneral = (
  form: Form,
  compiled: General["compiled"],
): General => {
  const gen8 = form.chunk("GEN8");
  if (gen8 === undefined || gen8.size < 128)
    throw new Error("GEN8 is missing or truncated.");
  const at = gen8.data;
  const bytecode = form.u8(at + 1);
  const info = form.u32(at + 68);
  const roomOrderAt = at + (bytecode >= 14 ? 128 : 124);
  const names = new Set(form.chunks.map(({ name }) => name));
  return {
    name: form.string(form.u32(at + 40)),
    display_name: form.string(form.u32(at + 100)),
    file_name: form.string(form.u32(at + 4)),
    config: form.string(form.u32(at + 8)),
    game_id: form.u32(at + 20),
    bytecode_version: bytecode,
    stored_version: [44, 48, 52, 56]
      .map((offset) => String(form.u32(at + offset)))
      .join("."),
    minimum_version:
      VERSION_CHUNKS.find(([chunk]) => names.has(chunk))?.[1] ?? null,
    compiled,
    debugger_disabled: form.u8(at) !== 0,
    window: { width: form.u32(at + 60), height: form.u32(at + 64) },
    flags: INFO_FLAGS.filter(([bit]) => (info & bit) !== 0).map(
      ([, name]) => name,
    ),
    built_at: builtAt(form.u64(at + 92)),
    steam_app_id: form.i32(at + 120),
    room_order: roomOrderAt + 4 <= at + gen8.size ? form.u32(roomOrderAt) : 0,
  };
};
