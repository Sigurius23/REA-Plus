import type { LuaBytecodeReport } from "../../../src/domain/lua/luaBytecode.js";

/**
 * Parsers for luac -l -l and luajit -bl listings, and the same projection of
 * an inspect_lua_bytecode report, so the two can be compared exactly.
 */

type Fn = LuaBytecodeReport["functions"][number];
type Ins = LuaBytecodeReport["instructions"][number];
type Constant = LuaBytecodeReport["constants"][number];

export interface Projection {
  readonly header: readonly unknown[];
  readonly code: readonly (readonly unknown[])[];
  readonly constants: readonly string[];
  readonly locals: readonly (readonly unknown[])[];
  readonly upvalues: readonly (readonly unknown[])[];
}

const ESCAPES: Readonly<Record<string, number>> = {
  a: 7,
  b: 8,
  f: 12,
  n: 10,
  r: 13,
  t: 9,
  v: 11,
  '"': 34,
  "\\": 92,
};

/** A luac string literal ("..." with C escapes and \ddd) as hex bytes. */
const luacString = (text: string): string => {
  if (!text.startsWith('"')) return text;
  const out: number[] = [];
  const body = text.slice(1, -1);
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index] ?? "";
    if (char !== "\\") {
      out.push(char.charCodeAt(0));
      continue;
    }
    const digits = /^\d{1,3}/u.exec(body.slice(index + 1))?.[0];
    if (digits !== undefined) {
      out.push(Number(digits));
      index += digits.length;
    } else {
      const next = body[index + 1] ?? "";
      out.push(ESCAPES[next] ?? next.charCodeAt(0));
      index += 1;
    }
  }
  return `S:${Buffer.from(out).toString("hex")}`;
};

const bytesOf = (constant: Constant): Buffer =>
  Buffer.from(constant.value, constant.binary ? "latin1" : "utf8");

/** luac -l -l, read as Latin-1 so bytes survive. */
export const parseLuacListing = (
  listing: string,
  version: number,
): Projection[] =>
  listing
    .split(/\n(?=(?:main|function) <)/u)
    .filter((block) => /^(main|function) </u.test(block.trim()))
    .map((raw) => {
      const block = raw.trim().split("\n");
      const header =
        /^(?:main|function) <[^>]*:(\d+),(\d+)> \((\d+) instructions?/u.exec(
          block[0] ?? "",
        );
      const counts =
        /^(\d+)(\+?) params?, (\d+) slots?, (\d+) upvalues?, (\d+) locals?, (\d+) constants?, (\d+) functions?/u.exec(
          block[1] ?? "",
        );
      const section = (name: string) => {
        const start = block.findIndex((line) => line.startsWith(`${name} (`));
        const rows: string[][] = [];
        if (start < 0) return rows;
        for (const line of block.slice(start + 1)) {
          if (!line.startsWith("\t")) break;
          rows.push(line.split("\t"));
        }
        return rows;
      };
      return {
        header: [
          ...(header?.slice(1, 4) ?? []),
          ...(counts?.slice(1) ?? []),
        ].map((value) => (/^\d+$/u.test(value) ? Number(value) : value)),
        code: block
          .filter((line) => /^\t\d+\t\[[\d-]+\]\t/u.test(line))
          .map((line) => {
            const [, pc = "", lineText = "", op = "", operands = ""] =
              /^\t(\d+)\t\[([\d-]+)\]\t(\S+)\s*\t?([^\t;]*)/u.exec(line) ?? [];
            return [
              Number(pc),
              lineText === "-" ? null : Number(lineText),
              op,
              operands.trim(),
            ];
          }),
        constants: section("constants").map((parts) =>
          luacString(parts.slice(version === 0x54 ? 3 : 2).join("\t")),
        ),
        locals: section("locals").map((parts) => [
          parts[2],
          Number(parts[3]),
          Number(parts[4]),
        ]),
        upvalues: section("upvalues").map((parts) =>
          version === 0x51
            ? [parts[2]]
            : [parts[2], Number(parts[3]), Number(parts[4])],
        ),
      };
    });

/** The luac projection of a report, function by function in luac's order (depth first). */
export const projectPuc = (
  report: {
    functions: readonly Fn[];
    instructions: readonly Ins[];
    constants: readonly Constant[];
    locals: LuaBytecodeReport["locals"];
    upvalues: LuaBytecodeReport["upvalues"];
  },
  version: number,
): Projection[] =>
  report.functions.map((fn) => {
    const constants = report.constants.filter((k) => k.function === fn.id);
    const upvalues = report.upvalues.filter((u) => u.function === fn.id);
    return {
      header: [
        fn.line_defined,
        fn.last_line_defined,
        fn.instructions,
        fn.params,
        fn.vararg ? "+" : "",
        fn.max_stack,
        fn.upvalues,
        fn.locals,
        fn.constants,
        fn.children,
      ],
      code: report.instructions
        .filter((ins) => ins.function === fn.id)
        .map((ins) => [ins.pc, ins.line, ins.op, ins.operands]),
      constants: constants.map((k) => {
        if (k.type === "string") return `S:${bytesOf(k).toString("hex")}`;
        // 5.3+ print floats that look integral with ".0".
        return k.type === "number" &&
          version >= 0x53 &&
          /^-?\d+$/u.test(k.value)
          ? `${k.value}.0`
          : k.value;
      }),
      locals: report.locals
        .filter((l) => l.function === fn.id)
        .map((l) => [l.name, l.start_pc, l.end_pc]),
      // 5.1 lists only named upvalues; a stripped chunk keeps the count but no names.
      upvalues: upvalues
        .filter((u) => version !== 0x51 || u.name !== null)
        .map((u) =>
          version === 0x51
            ? [u.name]
            : [u.name ?? "-", u.in_stack === true ? 1 : 0, u.slot],
        ),
    };
  });

/** luajit -bl: one block per prototype, children before parents. */
export const parseLuajitListing = (listing: string): string[][][] =>
  listing
    .split("-- BYTECODE --")
    .slice(1)
    .map((block) =>
      block
        .split("\n")
        .slice(1)
        .filter((line) => /^\d{4,}/u.test(line))
        .map((line) => {
          const cut = /\s+;\s+/u.exec(line);
          const head = cut === null ? line : line.slice(0, cut.index);
          const comment =
            cut === null ? "" : line.slice(cut.index + cut[0].length);
          const [pc = "", ...rest] = head
            .replace(/^(\d{4,})\s+(=>)?/u, "$1 ")
            .trim()
            .split(/\s+/u);
          return [
            String(Number(pc)),
            rest.join(" ").replace(/=> /u, "=>"),
            comment,
          ];
        }),
    );

const STRING_OPERANDS = /^(KSTR|GGET|GSET|TGETS|TSETS|ISEQS|ISNES|USETS)$/u;

/** A string constant as bc.lua shows it: control characters escaped, cut at 40 characters with "~". */
const bcString = (constant: Constant | undefined): string => {
  const raw =
    constant === undefined ? "" : bytesOf(constant).toString("latin1");
  const escaped = [...raw]
    .map((char) => {
      const code = char.charCodeAt(0);
      if (code >= 0x20 && code !== 0x7f) return char;
      return char === "\n"
        ? "\\n"
        : char === "\r"
          ? "\\r"
          : char === "\t"
            ? "\\t"
            : `\\${String(code).padStart(3, "0")}`;
    })
    .join("");
  return raw.length > 40 ? `"${escaped.slice(0, 40)}"~` : `"${escaped}"`;
};

/** The luajit -bl projection of a report: prototypes in post order, string comments as bc.lua renders them. */
export const projectJit = (report: {
  functions: readonly Fn[];
  instructions: readonly Ins[];
  constants: readonly Constant[];
}): string[][][] => {
  const children = new Map<string, Fn[]>();
  for (const fn of report.functions)
    if (fn.parent !== null)
      children.set(fn.parent, [...(children.get(fn.parent) ?? []), fn]);
  const order: Fn[] = [];
  const visit = (fn: Fn) => {
    for (const child of children.get(fn.id) ?? []) visit(child);
    order.push(fn);
  };
  const main = report.functions.find((fn) => fn.parent === null);
  if (main !== undefined) visit(main);
  return order.map((fn) =>
    report.instructions
      .filter((ins) => ins.function === fn.id)
      .map((ins) => {
        const index = ins.fields["c"] ?? ins.fields["d"];
        const constant = report.constants.find(
          (k) => k.function === fn.id && k.pool === "gc" && k.index === index,
        );
        return [
          String(ins.pc),
          `${ins.op} ${ins.operands}`.replace(/=> /u, "=>").trim(),
          STRING_OPERANDS.test(ins.op) ? bcString(constant) : "",
        ];
      }),
  );
};

/** Keep only the string comments of a luajit -bl projection; USETS prefixes the upvalue name (possibly empty) and " ; ". */
export const jitStringsOnly = (
  blocks: string[][][],
  ops: string[][][],
): string[][][] =>
  blocks.map((block, b) =>
    block.map((row, i) => {
      const op = (ops[b]?.[i]?.[1] ?? "").split(" ")[0] ?? "";
      if (!STRING_OPERANDS.test(op)) return [row[0] ?? "", row[1] ?? "", ""];
      const comment = row[2] ?? "";
      return [
        row[0] ?? "",
        row[1] ?? "",
        op === "USETS" ? comment.replace(/^[^"]*;\s*/u, "") : comment,
      ];
    }),
  );
