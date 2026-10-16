import { createPng } from "./rpgMakerFixture.js";

/**
 * GameMaker data files assembled in source with UndertaleModTool's layouts:
 * an IFF FORM of chunks, pointer lists of FORM-relative offsets, and string
 * references that point at the text just past each STRG length prefix.
 */

type Part =
  | { readonly kind: "bytes"; readonly bytes: Buffer }
  | { readonly kind: "ref"; readonly label: string; readonly add: number }
  | { readonly kind: "rel"; readonly label: string; readonly from: string };

/** A two-pass writer: labels mark offsets, refs are patched once layout is known. */
class Writer {
  readonly parts: Part[] = [];
  readonly labels = new Map<string, number>();
  #size = 0;

  get size(): number {
    return this.#size;
  }

  bytes(bytes: Buffer): this {
    this.parts.push({ kind: "bytes", bytes });
    this.#size += bytes.length;
    return this;
  }

  u32(value: number): this {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value >>> 0);
    return this.bytes(bytes);
  }

  i32(value: number): this {
    const bytes = Buffer.alloc(4);
    bytes.writeInt32LE(value);
    return this.bytes(bytes);
  }

  u16(value: number): this {
    const bytes = Buffer.alloc(2);
    bytes.writeUInt16LE(value);
    return this.bytes(bytes);
  }

  f32(value: number): this {
    const bytes = Buffer.alloc(4);
    bytes.writeFloatLE(value);
    return this.bytes(bytes);
  }

  mark(label: string): this {
    this.labels.set(label, this.#size);
    return this;
  }

  ref(label: string, add = 0): this {
    this.parts.push({ kind: "ref", label, add });
    this.#size += 4;
    return this;
  }

  /** A signed offset from the `from` label to `label` (CODE bytecode addresses). */
  rel(label: string, from: string): this {
    this.parts.push({ kind: "rel", label, from });
    this.#size += 4;
    return this;
  }

  str(text: string): this {
    return this.ref(`str:${text}`, 4);
  }

  align(to: number): this {
    return this.#size % to === 0
      ? this
      : this.bytes(Buffer.alloc(to - (this.#size % to)));
  }

  build(): Buffer {
    const out: Buffer[] = [];
    for (const part of this.parts) {
      if (part.kind === "bytes") {
        out.push(part.bytes);
        continue;
      }
      const target = this.labels.get(part.label);
      if (target === undefined) throw new Error(`Unknown label ${part.label}`);
      const value = Buffer.alloc(4);
      if (part.kind === "ref") value.writeUInt32LE(target + part.add);
      else value.writeInt32LE(target - (this.labels.get(part.from) ?? 0));
      out.push(value);
    }
    return Buffer.concat(out);
  }
}

const chunk = (
  writer: Writer,
  name: string,
  body: (writer: Writer) => void,
) => {
  writer.bytes(Buffer.from(name, "latin1"));
  const sizeAt = writer.parts.length;
  writer.u32(0);
  const start = writer.size;
  body(writer);
  const size = writer.size - start;
  const patched = Buffer.alloc(4);
  patched.writeUInt32LE(size);
  writer.parts[sizeAt] = { kind: "bytes", bytes: patched };
};

/** A pointer list: count, then a ref per entry label, then each entry. */
const list = (
  writer: Writer,
  prefix: string,
  entries: readonly ((writer: Writer) => void)[],
) => {
  writer.u32(entries.length);
  entries.forEach((_, index) => writer.ref(`${prefix}${String(index)}`));
  entries.forEach((entry, index) => {
    writer.mark(`${prefix}${String(index)}`);
    entry(writer);
  });
};

export const FIXTURE_STRINGS = [
  "fixture_game",
  "Fixture Game",
  "Default",
  "snd_jump",
  ".ogg",
  "snd_jump.ogg",
  "snd_music",
  ".mp3",
  "music.ogg",
  "audiogroup_default",
  "spr_player",
  "scr_move",
  "Player",
  "obj_player",
  "obj_wall",
  "rm_start",
  "Start",
  "seq_intro",
  "gml_Script_scr_move",
  "gml_GlobalScript_Player",
  "gml_Script_Player",
  "gml_Room_rm_start_Create",
  "score",
  "hp",
  "instance_create_layer",
  "show_debug_message",
] as const;

export interface GameMakerFixtureOptions {
  readonly bytecode?: 14 | 17;
  /** YYC: CODE, VARI and FUNC are present but empty. */
  readonly yyc?: boolean;
}

const general = (writer: Writer, bytecode: number) => {
  writer.bytes(Buffer.from([1, bytecode, 0, 0]));
  writer.str("fixture_game").str("Default").u32(100000).u32(10000000).u32(4242);
  writer.bytes(Buffer.alloc(16)).str("fixture_game");
  writer.u32(2).u32(0).u32(0).u32(0).u32(640).u32(360).u32(0x1030).u32(0);
  writer.bytes(Buffer.alloc(16));
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigUInt64LE(1767225600n);
  writer.bytes(timestamp).str("Fixture Game");
  writer.bytes(Buffer.alloc(16)).i32(480);
  if (bytecode >= 14) writer.u32(6502);
  writer.u32(1).u32(0);
};

const resources = (writer: Writer) => {
  chunk(writer, "SOND", (w) =>
    list(w, "sond", [
      (e) =>
        e
          .str("snd_jump")
          .u32(0x64)
          .str(".ogg")
          .str("snd_jump.ogg")
          .u32(0)
          .f32(1)
          .f32(1)
          .i32(0)
          .i32(0),
      (e) =>
        e
          .str("snd_music")
          .u32(0x64)
          .str(".mp3")
          .str("music.ogg")
          .u32(0)
          .f32(0.5)
          .f32(1)
          .i32(1)
          .i32(3),
    ]),
  );
  chunk(writer, "AGRP", (w) =>
    list(w, "agrp", [(e) => e.str("audiogroup_default")]),
  );
  chunk(writer, "SPRT", (w) =>
    list(w, "sprt", [
      (e) => {
        e.str("spr_player").u32(32).u32(48);
        for (let field = 0; field < 9; field += 1) e.u32(0);
        e.i32(16).i32(48).i32(-1).u32(3);
      },
    ]),
  );
  chunk(writer, "SCPT", (w) =>
    list(w, "scpt", [
      (e) => e.str("scr_move").i32(0),
      (e) => e.str("Player").i32(1 | 0x80000000),
    ]),
  );
  chunk(writer, "OBJT", (w) =>
    list(w, "objt", [
      (e) => e.str("obj_player").i32(0).u32(1).u32(0),
      (e) => e.str("obj_wall").i32(-1).u32(0).u32(1),
    ]),
  );
  chunk(writer, "ROOM", (w) =>
    list(w, "room", [
      (e) => {
        e.str("rm_start")
          .str("Start")
          .u32(640)
          .u32(360)
          .u32(60)
          .u32(1)
          .u32(0)
          .u32(1)
          .i32(3)
          .u32(0);
        e.ref("room0bg")
          .ref("room0views")
          .ref("room0objects")
          .ref("room0tiles");
        e.mark("room0bg")
          .u32(0)
          .mark("room0views")
          .u32(0)
          .mark("room0tiles")
          .u32(0);
        e.mark("room0objects").u32(2).ref("inst0").ref("inst1");
        e.mark("inst0")
          .i32(32)
          .i32(32)
          .i32(0)
          .mark("inst1")
          .i32(64)
          .i32(32)
          .i32(1);
      },
    ]),
  );
  chunk(writer, "SEQN", (w) => {
    w.u32(1);
    list(w, "seqn", [(e) => e.str("seq_intro").u32(0)]);
  });
};

const CODE = [
  ["gml_Script_scr_move", "blobA", 8, 1, 2],
  ["gml_GlobalScript_Player", "blobB", 12, 0, 0],
  ["gml_Script_Player", "blobB", 12, 3, 1],
  ["gml_Room_rm_start_Create", "blobC", 4, 0, 0],
] as const;

const code = (writer: Writer, bytecode: number, yyc: boolean) => {
  chunk(writer, "CODE", (w) => {
    if (yyc) return;
    if (bytecode <= 14) {
      list(
        w,
        "code",
        CODE.map(
          ([name, , length]) =>
            (e: Writer) =>
              e.str(name).u32(length).bytes(Buffer.alloc(length, 0xab)),
        ),
      );
      return;
    }
    // Bytecode 15+: the pointer list, then the bytecode blobs, then the entries pointing back at them.
    w.u32(CODE.length);
    CODE.forEach((_, index) => w.ref(`code${String(index)}`));
    w.mark("blobA")
      .bytes(Buffer.alloc(8, 0xa1))
      .mark("blobB")
      .bytes(Buffer.alloc(12, 0xb2));
    w.mark("blobC").bytes(Buffer.alloc(4, 0xc3));
    CODE.forEach(([name, blob, length, locals, args], index) => {
      w.mark(`code${String(index)}`)
        .str(name)
        .u32(length)
        .u16(locals)
        .u16(args | (index === 2 ? 0x8000 : 0));
      w.mark(`code${String(index)}addr`)
        .rel(blob, `code${String(index)}addr`)
        .u32(0);
    });
  });
  chunk(writer, "VARI", (w) => {
    if (yyc) return;
    if (bytecode >= 15) w.u32(2).u32(2).u32(3);
    for (const [name, type, id, uses] of [
      ["score", -5, 0, 4],
      ["hp", -1, 1, 7],
    ] as const)
      if (bytecode >= 15) w.str(name).i32(type).i32(id).u32(uses).i32(-1);
      else w.str(name).u32(uses).i32(-1);
  });
  chunk(writer, "FUNC", (w) => {
    if (yyc) return;
    if (bytecode >= 15) w.u32(2);
    w.str("instance_create_layer")
      .u32(2)
      .i32(-1)
      .str("show_debug_message")
      .u32(5)
      .i32(-1);
    if (bytecode >= 15) w.u32(0);
  });
};

const strings = (writer: Writer) =>
  chunk(writer, "STRG", (w) =>
    list(
      w,
      "strg",
      FIXTURE_STRINGS.map((text) => (e: Writer) => {
        const bytes = Buffer.from(text, "utf8");
        e.mark(`str:${text}`)
          .u32(bytes.length)
          .bytes(Buffer.concat([bytes, Buffer.alloc(1)]));
      }),
    ),
  );

export const FIXTURE_PNG = createPng(16, 8);

const media = (writer: Writer) => {
  chunk(writer, "TXTR", (w) => {
    list(w, "txtr", [
      (e) => e.u32(1).u32(0).ref("tex0"),
      (e) => e.u32(1).u32(0).ref("tex1"),
      (e) => e.u32(1).u32(0).u32(0),
    ]);
    w.align(128).mark("tex0").bytes(FIXTURE_PNG);
    const qoi = Buffer.alloc(12);
    qoi.write("fioq", 0, "latin1");
    qoi.writeUInt16LE(8, 4);
    qoi.writeUInt16LE(4, 6);
    w.align(128).mark("tex1").bytes(qoi).bytes(Buffer.alloc(20));
  });
  audio(writer);
};

const audio = (writer: Writer) =>
  chunk(writer, "AUDO", (w) =>
    list(w, "audo", [
      (e) => e.u32(12).bytes(Buffer.from("RIFF\0\0\0\0WAVE", "latin1")),
      (e) => e.u32(8).bytes(Buffer.from("OggS\0\0\0\0", "latin1")),
    ]),
  );

const form = (body: (writer: Writer) => void): Buffer => {
  const writer = new Writer();
  writer.bytes(Buffer.from("FORM", "latin1")).u32(0);
  body(writer);
  const bytes = writer.build();
  bytes.writeUInt32LE(bytes.length - 8, 4);
  return bytes;
};

/** A small game: two sounds, a sprite, scripts (one a 2.3 constructor), objects, a room and code. */
export const createGameMakerData = (
  options: GameMakerFixtureOptions = {},
): Buffer => {
  const bytecode = options.bytecode ?? 17;
  return form((writer) => {
    chunk(writer, "GEN8", (w) => general(w, bytecode));
    resources(writer);
    code(writer, bytecode, options.yyc === true);
    strings(writer);
    media(writer);
  });
};

/** An audiogroupN.dat: a FORM holding only AUDO. */
export const createGameMakerAudioGroup = (): Buffer =>
  form((writer) => audio(writer));

/** A runner executable with the data file appended after it. */
export const appendToRunner = (data: Buffer): Buffer =>
  Buffer.concat([Buffer.from("MZ"), Buffer.alloc(1022, 0x90), data]);

/** A data file whose sprite name points into the middle of a string. */
export const createMisalignedGameMakerData = (): Buffer => {
  const data = createGameMakerData();
  const sprite = data.indexOf(Buffer.from("SPRT", "latin1"));
  const entry = data.readUInt32LE(sprite + 12);
  data.writeUInt32LE(data.readUInt32LE(entry) + 2, entry);
  return data;
};
