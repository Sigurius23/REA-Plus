import type { ScriptToken } from "./GdscriptTokens.js";

/**
 * GDScript source rebuilt from compiled tokens, placed on the source lines
 * the tokens record. Indentation follows the token stream (tabs, one per
 * level); spacing is regenerated. Comments and blank lines are not stored.
 */

export interface SourceLine {
  readonly line: number;
  readonly text: string;
}

const OPERAND_KEYWORDS = new Set([
  "self",
  "super",
  "PI",
  "TAU",
  "INF",
  "NAN",
  "_",
]);
const CALLABLE_KEYWORDS = new Set([
  "preload",
  "assert",
  "yield",
  "super",
  "self",
  "export",
]);
const TIGHT_BEFORE = new Set([")", "]", ",", ":", ";", "."]);
const TIGHT_AFTER = new Set(["(", "[", ".", "$", "~", "!"]);
const UNARY = new Set(["-", "+", "~", "!", "%", "$"]);

/** Whether a token can end an operand, so a following "-" is binary. */
const endsOperand = (token: ScriptToken | undefined): boolean =>
  token !== undefined &&
  (token.role === "identifier" ||
    token.role === "literal" ||
    (token.role === "builtin" && token.type === "BUILT_IN_TYPE") ||
    [")", "]", "}"].includes(token.text) ||
    OPERAND_KEYWORDS.has(token.text));

class Row {
  readonly parts: string[] = [];
  previous: ScriptToken | undefined;
  /** The previous token was a unary operator, or a node path is open. */
  glued = false;
  path = false;

  constructor(
    readonly line: number,
    readonly level: number,
  ) {}

  spaced(token: ScriptToken): boolean {
    const previous = this.previous;
    if (previous === undefined || this.glued) return false;
    if (this.path) {
      if (token.text === "/" || previous.text === "/") return false;
      this.path = false;
    }
    if (TIGHT_BEFORE.has(token.text) || TIGHT_AFTER.has(previous.text))
      return false;
    // := is a colon and an equals sign in the token stream.
    if (previous.text === ":" && token.text === "=") {
      this.parts[this.parts.length - 1] = " :";
      return false;
    }
    if (token.text === "(" || token.text === "[")
      return !(
        previous.role === "identifier" ||
        previous.role === "builtin" ||
        previous.role === "annotation" ||
        [")", "]"].includes(previous.text) ||
        CALLABLE_KEYWORDS.has(previous.text)
      );
    return true;
  }

  add(token: ScriptToken): void {
    const unary = UNARY.has(token.text) && !endsOperand(this.previous);
    this.parts.push(`${this.spaced(token) ? " " : ""}${token.text}`);
    this.glued = unary;
    if (unary && (token.text === "$" || token.text === "%")) this.path = true;
    this.previous = token;
  }

  get text(): string {
    return `${"\t".repeat(this.level)}${this.parts.join("")}`;
  }
}

/** Indentation widths seen so far; a line's level is its depth in the stack. */
class Levels {
  readonly widths: number[] = [];

  level(width: number): number {
    while (this.widths.length > 0 && width < (this.widths.at(-1) ?? 0))
      this.widths.pop();
    if (width > (this.widths.at(-1) ?? 0)) this.widths.push(width);
    return this.widths.length;
  }
}

export const scriptSource = (tokens: readonly ScriptToken[]): SourceLine[] => {
  const rows = new Map<number, Row>();
  const levels = new Levels();
  const godot3 = tokens.some((token) => token.role === "newline");
  let pending: number | null = 0;
  let level = 0;
  let current: Row | undefined;
  let lastLine = 1;
  for (const token of tokens) {
    if (token.role === "newline") {
      pending = token.indent ?? 0;
      continue;
    }
    if (
      token.role === "eof" ||
      token.role === "indent" ||
      token.role === "dedent"
    )
      continue;
    const line = token.line ?? lastLine;
    const width = godot3 ? pending : token.indent;
    if (width !== null) {
      level = levels.level(width);
      pending = null;
    }
    if (current === undefined || current.line !== line) {
      const existing = rows.get(line);
      current = existing ?? new Row(line, width === null ? level + 1 : level);
      rows.set(line, current);
    }
    current.add(token);
    lastLine = line;
  }
  return [...rows.values()]
    .sort((left, right) => left.line - right.line)
    .map((row) => ({ line: row.line, text: row.text }));
};
