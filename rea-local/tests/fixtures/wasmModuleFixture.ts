/**
 * A small WebAssembly module assembled byte by byte: an Emscripten-style
 * import, three functions that call each other directly and indirectly,
 * SIMD and bulk-memory instructions, active and passive data with text, and
 * the name, producers, target_features, sourceMappingURL,
 * external_debug_info and DWARF custom sections toolchains write.
 */

const u32 = (value: number): number[] => {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest = Math.floor(rest / 128);
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return bytes;
};

const text = (value: string): number[] => [
  ...u32(Buffer.byteLength(value)),
  ...Buffer.from(value),
];

const vector = (items: readonly number[][]): number[] => [
  ...u32(items.length),
  ...items.flat(),
];

const section = (id: number, payload: readonly number[]): number[] => [
  id,
  ...u32(payload.length),
  ...payload,
];

const custom = (name: string, payload: readonly number[]): number[] =>
  section(0, [...text(name), ...payload]);

const I32 = 0x7f;
const END = 0x0b;
/** Signed LEB128, as i32.const immediates need. */
const s32 = (value: number): number[] => {
  const bytes: number[] = [];
  let rest = value;
  for (;;) {
    const byte = rest & 0x7f;
    rest >>= 7;
    const done =
      (rest === 0 && (byte & 0x40) === 0) ||
      (rest === -1 && (byte & 0x40) !== 0);
    bytes.push(done ? byte : byte | 0x80);
    if (done) return bytes;
  }
};
const i32Const = (value: number): number[] => [0x41, ...s32(value)];
const call = (index: number): number[] => [0x10, ...u32(index)];

export const WASM_FIXTURE = {
  // Imported function 0, then defined functions 1 (add), 2 (main), 3 (helper).
  types: ["(i32) -> ()", "(i32, i32) -> i32", "() -> ()"],
  greeting: "Hello, WebAssembly!",
  health: "player_health",
  passive: "passive segment text",
  score: "score_value",
  sourceMap: "game.wasm.map",
  debugFile: "game.debug.wasm",
} as const;

const body = (locals: readonly number[][], code: readonly number[]) => {
  const content = [...vector(locals.map((entry) => [...entry])), ...code, END];
  return [...u32(content.length), ...content];
};

const FUNCTIONS = {
  add: body([], [0x20, 0x00, 0x20, 0x01, 0x6a]),
  main: body(
    [[...u32(2), I32]],
    [
      ...i32Const(5),
      ...call(0),
      ...i32Const(1),
      ...i32Const(2),
      ...call(1),
      0x1a,
      ...i32Const(3),
      ...i32Const(4),
      ...call(1),
      0x1a,
      // v128.const, then drop
      0xfd,
      ...u32(12),
      ...Array.from({ length: 16 }, (_, index) => index),
      0x1a,
      // block; i32.const 0; br_if 0; end
      0x02,
      0x40,
      ...i32Const(0),
      0x0d,
      0x00,
      END,
      // call_indirect (type 2) through table 0
      ...i32Const(0),
      0x11,
      0x02,
      0x00,
      // memory.copy 0 0
      ...i32Const(0),
      ...i32Const(0),
      ...i32Const(0),
      0xfc,
      ...u32(10),
      0x00,
      0x00,
      ...call(3),
    ],
  ),
  helper: body([], [...i32Const(7), ...i32Const(8), ...call(1), 0x1a]),
  // 0xFF is not an instruction; readers must stop rather than guess.
  undecodable: body([], [...i32Const(0), 0xff, 0x1a]),
};

/** Assemble the fixture module; `undecodable` appends a body with an unknown opcode. */
export const createWasmModule = (
  options: { readonly undecodable?: boolean } = {},
): Buffer => {
  const extra = options.undecodable === true;
  const names = custom("name", [
    ...section(0, text("fixture")),
    ...section(
      1,
      vector([
        [1, ...text("add")],
        [2, ...text("main")],
      ]),
    ),
    ...section(9, vector([[0, ...text("greetings")]])),
  ]);
  return Buffer.from([
    0x00,
    0x61,
    0x73,
    0x6d,
    0x01,
    0x00,
    0x00,
    0x00,
    ...section(
      1,
      vector([
        [0x60, ...vector([[I32]]), ...vector([])],
        [0x60, ...vector([[I32], [I32]]), ...vector([[I32]])],
        [0x60, ...vector([]), ...vector([])],
      ]),
    ),
    ...section(
      2,
      vector([
        [...text("env"), ...text("emscripten_run_script"), 0x00, 0x00],
        [...text("env"), ...text("memory"), 0x02, 0x01, 0x01, 0x10],
        [...text("env"), ...text("__stack_pointer"), 0x03, I32, 0x01],
      ]),
    ),
    ...section(3, vector(extra ? [[1], [2], [2], [2]] : [[1], [2], [2]])),
    ...section(4, vector([[0x70, 0x00, 0x01]])),
    ...section(6, vector([[I32, 0x00, ...i32Const(42), END]])),
    ...section(
      7,
      vector([
        [...text("add"), 0x00, 1],
        [...text("main"), 0x00, 2],
        [...text("helper_export"), 0x00, 3],
        [...text("memory"), 0x02, 0],
      ]),
    ),
    ...section(8, u32(3)),
    ...section(10, [
      ...u32(extra ? 4 : 3),
      ...FUNCTIONS.add,
      ...FUNCTIONS.main,
      ...FUNCTIONS.helper,
      ...(extra ? FUNCTIONS.undecodable : []),
    ]),
    ...section(
      11,
      vector([
        [
          0x00,
          ...i32Const(1024),
          END,
          ...text(`${WASM_FIXTURE.greeting}\0${WASM_FIXTURE.health}\0ab\0`),
        ],
        [0x01, ...text(WASM_FIXTURE.passive)],
        [
          0x02,
          0x00,
          ...i32Const(2048),
          END,
          ...u32(2 + WASM_FIXTURE.score.length),
          0x01,
          0x02,
          ...Buffer.from(WASM_FIXTURE.score),
        ],
      ]),
    ),
    ...names,
    ...custom(
      "producers",
      vector([
        [...text("language"), ...vector([[...text("C"), ...text("")]])],
        [
          ...text("processed-by"),
          ...vector([[...text("clang"), ...text("19.1.0")]]),
        ],
      ]),
    ),
    ...custom(
      "target_features",
      vector([
        [0x2b, ...text("simd128")],
        [0x2b, ...text("bulk-memory")],
      ]),
    ),
    ...custom("sourceMappingURL", text(WASM_FIXTURE.sourceMap)),
    ...custom("external_debug_info", text(WASM_FIXTURE.debugFile)),
    // Starts like a short name; previews must not report it as text.
    ...custom(".debug_info", [0x05, 0x00, 0x00, 0x00, 0x04, 0x00]),
  ]);
};

/** The 8-byte preamble of a component-model binary (layer 1, version 0xd). */
export const COMPONENT_PREAMBLE = Buffer.from([
  0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00,
]);
