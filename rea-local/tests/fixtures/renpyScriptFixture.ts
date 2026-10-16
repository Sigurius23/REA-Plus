import { deflateSync } from "node:zlib";

/**
 * Compiled Ren'Py scripts built in source: a protocol-2 pickle of
 * (data, statements) the way Ren'Py 8 stores slotted AST nodes, wrapped in
 * the RENPY RPC2 slot container.
 */

type Value =
  | null
  | boolean
  | number
  | string
  | readonly Value[]
  | { readonly tuple: readonly Value[] }
  | { readonly dict: readonly (readonly [string, Value])[] }
  | AstNode;

interface AstNode {
  readonly module: string;
  readonly name: string;
  readonly args?: readonly Value[];
  /** Slot state, stored as Ren'Py does: (None, {slot: value}). */
  readonly slots?: Readonly<Record<string, Value>>;
  /** Plain BUILD state such as PyCode's tuple. */
  readonly state?: Value;
}

const isNode = (value: Value): value is AstNode =>
  typeof value === "object" && value !== null && "module" in value;

const u32 = (value: number) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};

/** A protocol-2 pickler covering the opcodes Ren'Py scripts use. */
const pickle = (root: Value): Buffer => {
  const out: Buffer[] = [Buffer.from([0x80, 2])];
  const op = (...bytes: number[]) => out.push(Buffer.from(bytes));
  const write = (value: Value): void => {
    if (value === null) op(0x4e);
    else if (value === true) op(0x88);
    else if (value === false) op(0x89);
    else if (typeof value === "number") {
      op(0x4a);
      out.push(Buffer.from(Int32Array.of(value).buffer));
    } else if (typeof value === "string") {
      const bytes = Buffer.from(value, "utf8");
      op(0x58);
      out.push(u32(bytes.length), bytes);
    } else if (Array.isArray(value)) {
      op(0x5d, 0x28);
      for (const item of value as readonly Value[]) write(item);
      op(0x65);
    } else if (isNode(value)) {
      out.push(Buffer.from(`c${value.module}\n${value.name}\n`, "latin1"));
      op(0x28);
      for (const arg of value.args ?? []) write(arg);
      op(0x74, 0x81);
      if (value.slots !== undefined) {
        write({ tuple: [null, { dict: Object.entries(value.slots) }] });
        op(0x62);
      } else if (value.state !== undefined) {
        write(value.state);
        op(0x62);
      }
    } else if ("tuple" in value) {
      op(0x28);
      for (const item of value.tuple) write(item);
      op(0x74);
    } else {
      op(0x7d, 0x28);
      const { dict } = value as {
        readonly dict: readonly (readonly [string, Value])[];
      };
      for (const [key, item] of dict) {
        write(key);
        write(item);
      }
      op(0x75);
    }
  };
  write(root);
  op(0x2e);
  return Buffer.concat(out);
};

const FILE = "game/script.rpy";

const node = (
  name: string,
  line: number,
  slots: Readonly<Record<string, Value>>,
): AstNode => ({
  module: "renpy.ast",
  name,
  slots: { linenumber: line, filename: FILE, ...slots },
});

const expression = (source: string, line: number): AstNode => ({
  module: "renpy.astsupport",
  name: "PyExpr",
  args: [source, { tuple: [FILE, line, 3, 1234, 0] }],
});

const code = (source: string, line: number): AstNode => ({
  module: "renpy.ast",
  name: "PyCode",
  state: {
    tuple: [1, expression(source, line), { tuple: [FILE, line] }, "eval"],
  },
});

/** One short visual novel: a character, a branching menu and a French translation. */
export const createRenpyStatements = (merged: boolean): Value => {
  const say = (line: number, who: string | null, what: string, id: string) =>
    merged
      ? node("TranslateSay", line, {
          ...(who === null ? {} : { who }),
          what,
          identifier: id,
        })
      : node("Say", line, { ...(who === null ? {} : { who }), what });
  return [
    node("Init", 1, {
      block: [
        node("Define", 1, {
          varname: "e",
          code: code('Character("Eileen")', 1),
        }),
        node("Default", 2, { varname: "met_eileen", code: code("False", 2) }),
        node("Image", 3, {
          imgname: { tuple: ["bg", "room"] },
          code: code('"room.png"', 3),
        }),
      ],
    }),
    node("Label", 5, {
      _name: "start",
      block: [
        say(6, "e", "Hello, {b}world{/b}! 100%% sure.", "start_1a2b3c4d"),
        say(7, null, "The room is quiet.", "start_5e6f7a8b"),
        node("Menu", 9, {
          items: [
            { tuple: ["Where to?", "True", null] },
            {
              tuple: [
                "Go left",
                "True",
                [node("Jump", 11, { target: "left" })],
              ],
            },
            {
              tuple: [
                "Ask about the {i}book{/i}",
                expression("met_eileen", 12),
                [
                  node("Call", 13, { label: "book_talk" }),
                  node("Jump", 14, { target: "left" }),
                ],
              ],
            },
          ],
        }),
      ],
    }),
    node("Label", 16, {
      _name: "left",
      block: [
        say(17, "e", "You went left.", "left_9c0d1e2f"),
        node("Jump", 18, { target: "ending", expression: true }),
      ],
    }),
    node("Label", 20, { _name: "book_talk", block: [node("Return", 21, {})] }),
    node("Translate", 23, {
      identifier: "start_1a2b3c4d",
      language: "french",
      block: [
        node("Say", 24, { who: "e", what: "Bonjour, {b}le monde{/b} !" }),
      ],
    }),
    node("Init", 26, {
      block: [
        node("TranslateString", 27, {
          language: "french",
          old: "Go left",
          new: "Aller à gauche",
        }),
      ],
    }),
    node("Screen", 29, {
      screen: {
        module: "renpy.sl2.slast",
        name: "SLScreen",
        state: { dict: [["name", "hud"]] },
      },
    }),
  ];
};

const scriptPickle = (merged: boolean) =>
  pickle({
    tuple: [
      {
        dict: [
          ["version", 5003000],
          ["key", "fixture"],
        ],
      },
      createRenpyStatements(merged),
    ],
  });

/** A RENPY RPC2 file with slot 1 (Say) and slot 2 (TranslateSay), as Ren'Py 8 writes. */
export const createRenpyScript = (
  options: { slots?: readonly (1 | 2)[] } = {},
): Buffer => {
  const slots = options.slots ?? [1, 2];
  const datas = slots.map((slot) => deflateSync(scriptPickle(slot === 2)));
  const header = Buffer.from("RENPY RPC2", "latin1");
  const table = Buffer.alloc(12 * (slots.length + 1));
  let at = header.length + table.length;
  slots.forEach((slot, index) => {
    table.writeUInt32LE(slot, index * 12);
    table.writeUInt32LE(at, index * 12 + 4);
    table.writeUInt32LE(datas[index]?.length ?? 0, index * 12 + 8);
    at += datas[index]?.length ?? 0;
  });
  return Buffer.concat([header, table, ...datas, Buffer.alloc(16, 0xaa)]);
};

/** Ren'Py before 6.18: the whole file is one zlib stream. */
export const createLegacyRenpyScript = (): Buffer =>
  deflateSync(scriptPickle(false));

/** A script whose pickle names os.system, which REA+ must refuse without running. */
export const createHostileRenpyScript = (): Buffer => {
  const evil = Buffer.from(
    "800263706f7369780a73797374656d0a7100580a0000006563686f2070776e656471018571025271032e",
    "hex",
  );
  const data = deflateSync(evil);
  const table = Buffer.alloc(24);
  table.writeUInt32LE(1, 0);
  table.writeUInt32LE(10 + 24, 4);
  table.writeUInt32LE(data.length, 8);
  return Buffer.concat([Buffer.from("RENPY RPC2", "latin1"), table, data]);
};
