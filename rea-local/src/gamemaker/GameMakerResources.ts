import type {
  GameMakerDataReport,
  GameMakerResourceKind,
} from "../domain/gamemaker/gameMakerData.js";
import type { Form } from "./GameMakerForm.js";

type Resource = GameMakerDataReport["resources"][number];
type Code = GameMakerDataReport["code"][number];
type Symbol = GameMakerDataReport["symbols"][number];
type Texture = GameMakerDataReport["textures"][number];
type Audio = GameMakerDataReport["audio"][number];
type Fields = Resource["fields"];

/** Names resolved across resource lists (sprite ids, code ids). */
export interface Lookup {
  readonly sprites: readonly (string | null)[];
  readonly code: readonly (string | null)[];
  readonly bytecode: number;
}

interface ResourceChunk {
  readonly chunk: string;
  readonly kind: GameMakerResourceKind;
  /** Bytes before the pointer list (a format version in newer chunks). */
  readonly skip?: number;
  readonly nameAt?: number;
  readonly fields?: (form: Form, entry: number, lookup: Lookup) => Fields;
}

const byId = (names: readonly (string | null)[], id: number): string | null =>
  id >= 0 ? (names[id] ?? null) : null;

const round = (value: number): number => Math.round(value * 1000) / 1000;

/**
 * Only fields whose offsets UndertaleModTool reads the same way in every
 * supported version; everything after a version-dependent field is left out.
 */
const RESOURCE_CHUNKS: readonly ResourceChunk[] = [
  {
    chunk: "SOND",
    kind: "sound",
    fields: (form, at, lookup) => {
      // Regular sounds name their audio group from bytecode 14; others store a preload flag there.
      const grouped =
        (form.u32(at + 4) & 0x64) === 0x64 && lookup.bytecode >= 14;
      return {
        type: form.string(form.u32(at + 8)),
        file: form.string(form.u32(at + 12)),
        volume: round(form.f32(at + 20)),
        pitch: round(form.f32(at + 24)),
        audio_group: grouped ? form.i32(at + 28) : null,
        audio_file: form.i32(at + 32),
      };
    },
  },
  { chunk: "AGRP", kind: "audio_group" },
  {
    chunk: "SPRT",
    kind: "sprite",
    fields: (form, at) => ({
      width: form.u32(at + 4),
      height: form.u32(at + 8),
      origin_x: form.i32(at + 48),
      origin_y: form.i32(at + 52),
    }),
  },
  { chunk: "BGND", kind: "background" },
  { chunk: "PATH", kind: "path" },
  {
    chunk: "SCPT",
    kind: "script",
    fields: (form, at, lookup) => {
      const id = form.i32(at + 4);
      const constructor = id < -1;
      return {
        code: byId(lookup.code, constructor ? id & 0x7fffffff : id),
        constructor,
      };
    },
  },
  { chunk: "SHDR", kind: "shader" },
  {
    chunk: "FONT",
    kind: "font",
    fields: (form, at) => ({ display_name: form.string(form.u32(at + 4)) }),
  },
  { chunk: "TMLN", kind: "timeline" },
  {
    chunk: "OBJT",
    kind: "object",
    fields: (form, at, lookup) => ({
      sprite: byId(lookup.sprites, form.i32(at + 4)),
      visible: form.u32(at + 8) !== 0,
    }),
  },
  {
    chunk: "ROOM",
    kind: "room",
    fields: (form, at, lookup) => {
      const instances = form.u32(at + 48);
      return {
        caption: form.string(form.u32(at + 4)),
        width: form.u32(at + 8),
        height: form.u32(at + 12),
        speed: form.u32(at + 16),
        persistent: form.u32(at + 20) !== 0,
        creation_code: byId(lookup.code, form.i32(at + 32)),
        instances: instances === 0 ? 0 : form.u32(instances),
      };
    },
  },
  {
    chunk: "EXTN",
    kind: "extension",
    nameAt: 4,
    fields: (form, at) => ({ folder: form.string(form.u32(at)) }),
  },
  { chunk: "TGIN", kind: "texture_group", skip: 4 },
  { chunk: "ACRV", kind: "animation_curve", skip: 4 },
  { chunk: "SEQN", kind: "sequence", skip: 4 },
  { chunk: "PSYS", kind: "particle_system", skip: 4 },
  { chunk: "PSEM", kind: "particle_emitter", skip: 4 },
];

const entriesOf = (form: Form, name: string, skip = 0): number[] => {
  const chunk = form.chunk(name);
  return chunk === undefined ? [] : form.pointerList(chunk, skip);
};

const namesOf = (form: Form, chunk: string): (string | null)[] =>
  entriesOf(form, chunk).map((at) =>
    at === 0 ? null : form.string(form.u32(at)),
  );

export const lookupOf = (form: Form, bytecode: number): Lookup => ({
  sprites: namesOf(form, "SPRT"),
  code: namesOf(form, "CODE"),
  bytecode,
});

/** Every named resource, in chunk order and list order. */
export const readResources = (form: Form, lookup: Lookup): Resource[] =>
  RESOURCE_CHUNKS.flatMap(({ chunk, kind, skip, nameAt, fields }) =>
    entriesOf(form, chunk, skip).flatMap((at, index) =>
      at === 0
        ? []
        : [
            {
              kind,
              index,
              name: form.string(form.u32(at + (nameAt ?? 0))),
              offset: form.start + at,
              fields: fields?.(form, at, lookup) ?? {},
            },
          ],
    ),
  );

/** GML bytecode entries; YYC builds have none. */
export const readCode = (form: Form, bytecode: number): Code[] => {
  const roots = new Set<number>();
  return entriesOf(form, "CODE").map((at, index) => {
    const length = form.u32(at + 4);
    if (bytecode <= 14)
      return {
        index,
        name: form.string(form.u32(at)),
        length,
        locals: null,
        arguments: null,
        bytecode_offset: form.start + at + 8,
        shared: false,
      };
    const address = at + 12 + form.i32(at + 12);
    const shared = length > 0 && roots.has(address);
    if (length > 0) roots.add(address);
    return {
      index,
      name: form.string(form.u32(at)),
      length,
      locals: form.u16(at + 8),
      arguments: form.u16(at + 10) & 0x7fff,
      bytecode_offset: form.start + address,
      shared,
    };
  });
};

/** FUNC and VARI: the functions and variables the bytecode references. */
export const readSymbols = (form: Form, bytecode: number): Symbol[] => {
  const symbols: Symbol[] = [];
  const functions = form.chunk("FUNC");
  if (functions !== undefined && functions.size > 0) {
    const modern = bytecode >= 15;
    const count = modern
      ? form.u32(functions.data)
      : Math.floor(functions.size / 12);
    const start = functions.data + (modern ? 4 : 0);
    for (
      let index = 0;
      index < count && (index + 1) * 12 <= functions.size;
      index += 1
    ) {
      const at = start + index * 12;
      symbols.push({
        kind: "function",
        index,
        name: form.string(form.u32(at)),
        occurrences: form.u32(at + 4),
        instance_type: null,
        variable_id: null,
      });
    }
  }
  const variables = form.chunk("VARI");
  if (variables !== undefined && variables.size > 0) {
    const modern = bytecode >= 15;
    const size = modern ? 20 : 12;
    const start = variables.data + (modern ? 12 : 0);
    const count = Math.floor((variables.size - (modern ? 12 : 0)) / size);
    for (let index = 0; index < count; index += 1) {
      const at = start + index * size;
      symbols.push({
        kind: "variable",
        index,
        name: form.string(form.u32(at)),
        occurrences: form.u32(at + (modern ? 12 : 4)),
        instance_type: modern ? form.i32(at + 4) : null,
        variable_id: modern ? form.i32(at + 8) : null,
      });
    }
  }
  return symbols;
};

/** STRG entries: a 32-bit length then the text; references point at the text. */
export const readStrings = (form: Form): GameMakerDataReport["strings"] =>
  entriesOf(form, "STRG").map((at, index) => ({
    index,
    offset: form.start + at + 4,
    text: form.string(at + 4) ?? "",
  }));

const imageAt = (
  form: Form,
  at: number,
): Pick<Texture, "format" | "width" | "height"> | null => {
  const head = form.slice(at, 24);
  if (head.readUInt32BE(0) === 0x89504e47)
    return {
      format: "png",
      width: head.readUInt32BE(16),
      height: head.readUInt32BE(20),
    };
  const magic = head.subarray(0, 4).toString("latin1");
  if (magic === "fioq" || magic === "2zoq")
    return {
      format: magic === "fioq" ? "qoi" : "bz2-qoi",
      width: head.readUInt16LE(4),
      height: head.readUInt16LE(6),
    };
  return null;
};

/**
 * TXTR entry layouts grow with the runtime (mip, block size, dimensions);
 * the blob pointer is the field that points at a PNG or GameMaker QOI header.
 */
export const readTextures = (form: Form): Texture[] => {
  const chunk = form.chunk("TXTR");
  if (chunk === undefined) return [];
  const end = chunk.data + chunk.size;
  const entries = form.pointerList(chunk);
  // Entries are contiguous, so the smallest gap is the entry size; never scan into the next one.
  const gaps = entries
    .slice(1)
    .map((at, index) => at - (entries[index] ?? 0))
    .filter((gap) => gap > 0);
  const fields = Math.min(
    7,
    gaps.length === 0 ? 7 : Math.floor(Math.min(...gaps) / 4),
  );
  const found = entries.map((at) => {
    for (
      let field = 0;
      field < fields && at + field * 4 + 4 <= end;
      field += 1
    ) {
      const pointer = form.u32(at + field * 4);
      if (pointer < chunk.data || pointer + 24 > end) continue;
      const image = imageAt(form, pointer);
      if (image !== null) return { pointer, image };
    }
    return null;
  });
  const starts = found
    .flatMap((entry) => (entry === null ? [] : [entry.pointer]))
    .sort((a, b) => a - b);
  return found.map((entry, index) => {
    if (entry === null)
      return {
        index,
        offset: null,
        span: null,
        format: "external" as const,
        width: null,
        height: null,
      };
    const next = starts.find((start) => start > entry.pointer) ?? end;
    return {
      index,
      offset: form.start + entry.pointer,
      span: next - entry.pointer,
      ...entry.image,
    };
  });
};

/** AUDO: each entry is a 32-bit length then the audio file. */
export const readAudio = (
  form: Form,
  resources: readonly Resource[],
): Audio[] => {
  const users = new Map<number, string[]>();
  for (const sound of resources)
    if (sound.kind === "sound" && (sound.fields["audio_group"] ?? 0) === 0) {
      const file = sound.fields["audio_file"];
      if (typeof file === "number" && file >= 0)
        users.set(file, [...(users.get(file) ?? []), sound.name ?? ""]);
    }
  return entriesOf(form, "AUDO").map((at, index) => {
    const bytes = form.u32(at);
    const magic = form.slice(at + 4, Math.min(4, bytes)).toString("latin1");
    const format =
      magic === "RIFF"
        ? "wav"
        : magic === "OggS"
          ? "ogg"
          : form
                .slice(at + 4, Math.min(bytes, 4096))
                .every((byte) => byte === 0)
            ? "empty"
            : "unknown";
    return {
      index,
      offset: form.start + at + 4,
      bytes,
      format,
      sounds: users.get(index) ?? [],
    };
  });
};
