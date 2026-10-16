import { floatText, quoted } from "../../../src/godot/GodotBytes.js";

/**
 * A small GDScript lexer, written from Godot's tokenizer documentation and
 * independent of the compiled-token reader, so tests can compare the tokens
 * Godot compiled with the tokens of the original source. Literals are
 * reduced to their values, printed the way inspect_godot_file prints them.
 */

export interface LexedToken {
  readonly text: string;
  readonly line: number;
  readonly kind?: "identifier" | "literal" | "other";
}

const OPERATORS = [
  "**=",
  "<<=",
  ">>=",
  "...",
  "**",
  "<<",
  ">>",
  "==",
  "!=",
  "<=",
  ">=",
  "&&",
  "||",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "&=",
  "|=",
  "^=",
  "->",
  "..",
  "+",
  "-",
  "*",
  "/",
  "%",
  "=",
  "<",
  ">",
  "!",
  "&",
  "|",
  "^",
  "~",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  ",",
  ";",
  ".",
  ":",
  "$",
  "?",
  "`",
];

/** Godot 3 folds these spellings into one token each. */
const GODOT3_ALIASES: Readonly<Record<string, string>> = {
  "&&": "and",
  "||": "or",
  "!": "not",
};

const ESCAPES: Readonly<Record<string, string>> = {
  n: "\n",
  t: "\t",
  r: "\r",
  a: "\u0007",
  b: "\b",
  f: "\f",
  v: "\v",
  '"': '"',
  "'": "'",
  "\\": "\\",
};

/** Godot 4 words that are keywords, not identifiers (gdscript_tokenizer.cpp). */
const KEYWORDS4 = new Set(
  `if elif else for while break continue pass return match when as assert await
breakpoint class class_name const enum extends func in is namespace preload self
signal static super trait var void yield and or not PI TAU INF NAN true false null`.split(
    /\s+/u,
  ),
);

/** Tokens after which Godot 4 reads "-1" as a minus and a 1 (can_precede_bin_op). */
const precedesBinary = (token: LexedToken | undefined): boolean =>
  token !== undefined &&
  (token.kind === "identifier" ||
    token.kind === "literal" ||
    ["self", "]", "}", ")", "PI", "TAU", "INF", "NAN"].includes(token.text));

const IDENTIFIER_START = /[\p{L}_]/u;
const IDENTIFIER_PART = /[\p{L}\p{N}_]/u;

class Lexer {
  at = 0;
  line = 1;
  readonly tokens: LexedToken[] = [];

  constructor(
    readonly source: string,
    readonly major: 3 | 4,
  ) {}

  peek(offset = 0): string {
    return this.source[this.at + offset] ?? "";
  }

  push(
    text: string,
    line: number,
    kind: "identifier" | "literal" | "other" = "other",
  ): void {
    this.tokens.push({ text, line, kind });
  }

  /** A quoted string from the opening quote; raw strings keep backslashes. */
  string(raw: boolean): string {
    const quote = this.peek();
    const triple = this.source.startsWith(quote.repeat(3), this.at);
    const close = triple ? quote.repeat(3) : quote;
    this.at += close.length;
    let value = "";
    while (!this.source.startsWith(close, this.at)) {
      const char = this.peek();
      if (char === "")
        throw new Error(`Unterminated string at line ${String(this.line)}`);
      if (char === "\n") this.line += 1;
      if (char === "\\" && !raw) {
        const next = this.peek(1);
        if (next === "\n") {
          this.line += 1;
          this.at += 2;
          continue;
        }
        if (next === "u" || next === "U") {
          const digits = next === "u" ? 4 : 6;
          value += String.fromCodePoint(
            parseInt(this.source.slice(this.at + 2, this.at + 2 + digits), 16),
          );
          this.at += 2 + digits;
          continue;
        }
        value += ESCAPES[next] ?? next;
        this.at += 2;
        continue;
      }
      if (
        char === "\\" &&
        raw &&
        (this.peek(1) === quote || this.peek(1) === "\\")
      ) {
        value += char + this.peek(1);
        this.at += 2;
        continue;
      }
      value += char;
      this.at += 1;
    }
    this.at += close.length;
    return value;
  }

  number(): string {
    const rest = this.source.slice(this.at);
    const hex = /^0[xX][0-9a-fA-F_]+/u.exec(rest) ?? /^0[bB][01_]+/u.exec(rest);
    if (hex !== null) {
      this.at += hex[0].length;
      const digits = hex[0].replaceAll("_", "");
      return BigInt(
        digits.toLowerCase().startsWith("0b") ? `0b${digits.slice(2)}` : digits,
      ).toString();
    }
    const match =
      /^[+-]?(\d[\d_]*)?(\.[\d_]*)?([eE][+-]?\d[\d_]*)?/u.exec(rest)?.[0] ?? "";
    this.at += match.length;
    const clean = match.replaceAll("_", "");
    return /[.eE]/u.test(clean)
      ? floatText(Number(clean), false)
      : BigInt(clean).toString();
  }

  /** A string literal with an optional prefix: r (raw), & (StringName), ^ or @ (NodePath). */
  prefixedString(): boolean {
    const char = this.peek();
    const next = this.peek(1);
    const prefixes = this.major === 4 ? ["r", "&", "^"] : ["@"];
    if (!prefixes.includes(char) || (next !== '"' && next !== "'"))
      return false;
    const line = this.line;
    this.at += 1;
    const value = this.string(char === "r");
    this.push(
      char === "r" ? quoted(value) : `${char}${quoted(value)}`,
      line,
      "literal",
    );
    return true;
  }

  word(): void {
    const line = this.line;
    const start = this.at;
    while (IDENTIFIER_PART.test(this.peek())) this.at += 1;
    const word = this.source.slice(start, this.at);
    const literal = ["true", "false", "null"].includes(word);
    this.push(
      word,
      line,
      literal ? "literal" : KEYWORDS4.has(word) ? "other" : "identifier",
    );
  }

  /** Whitespace, line continuations and comments; true when one was skipped. */
  layout(char: string): boolean {
    if (char === "\n") {
      this.line += 1;
      this.at += 1;
    } else if (char === " " || char === "\t" || char === "\r") this.at += 1;
    else if (
      char === "\\" &&
      (this.peek(1) === "\n" || this.peek(1) === "\r")
    ) {
      this.at += this.peek(1) === "\r" ? 3 : 2;
      this.line += 1;
    } else if (char === "#") {
      while (this.peek() !== "\n" && this.peek() !== "") this.at += 1;
    } else return false;
    return true;
  }

  /** Godot 4 reads a sign before a digit as part of the number unless the previous token could end an operand. */
  startsNumber(char: string): boolean {
    const digitNext = /\d/u.test(this.peek(1));
    return (
      /\d/u.test(char) ||
      (char === "." && digitNext) ||
      (this.major === 4 &&
        (char === "-" || char === "+") &&
        digitNext &&
        !precedesBinary(this.tokens.at(-1)))
    );
  }

  operator(char: string): void {
    const operator = OPERATORS.find((op) =>
      this.source.startsWith(op, this.at),
    );
    if (operator === undefined)
      throw new Error(
        `Unexpected ${JSON.stringify(char)} at line ${String(this.line)}`,
      );
    this.at += operator.length;
    this.push(
      this.major === 3 ? (GODOT3_ALIASES[operator] ?? operator) : operator,
      this.line,
    );
  }

  step(): void {
    const char = this.peek();
    if (this.layout(char) || this.prefixedString()) return;
    if (char === '"' || char === "'") {
      const line = this.line;
      const value = quoted(this.string(false));
      // Godot 3 dates a string by the line it ends on, Godot 4 by where it starts.
      this.push(value, this.major === 3 ? this.line : line, "literal");
    } else if (this.startsNumber(char))
      this.push(this.number(), this.line, "literal");
    else if (char === "@" && this.major === 4) {
      const line = this.line;
      this.at += 1;
      this.word();
      const last = this.tokens.pop();
      this.push(`@${last?.text ?? ""}`, line);
    } else if (IDENTIFIER_START.test(char)) this.word();
    else this.operator(char);
  }
}

/** The tokens of GDScript source, without layout or comments. */
export const lexGdscript = (source: string, major: 3 | 4): LexedToken[] => {
  const lexer = new Lexer(source.replace(/^﻿/u, ""), major);
  while (lexer.at < lexer.source.length) lexer.step();
  return lexer.tokens;
};
