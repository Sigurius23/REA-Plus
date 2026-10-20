import { inflateSync } from "node:zlib";

import { GameArchiveError } from "../gamearchives/GameArchiveTypes.js";
import {
  decodeSafePickle,
  PickleObject,
  type PickleValue,
} from "../gamearchives/SafePickle.js";

/** A file that is not a compiled Ren'Py script. */
export class RenpyScriptError extends Error {}

const fail = (message: string): never => {
  throw new RenpyScriptError(message);
};

const HEADER = "RENPY RPC2";
const MAX_SCRIPT_BYTES = 512 * 1024 * 1024;

/** Ren'Py and game-store classes become inert records; nothing is imported. */
const allowedClass = (module: string, name: string): boolean =>
  module === "renpy" ||
  module.startsWith("renpy.") ||
  module === "store" ||
  module.startsWith("store.") ||
  ((module === "builtins" || module === "__builtin__") &&
    ["list", "set", "frozenset", "dict", "tuple", "object"].includes(name)) ||
  (module === "collections" &&
    (name === "defaultdict" || name === "OrderedDict")) ||
  ((module === "copy_reg" || module === "copyreg") &&
    name === "_reconstructor");

export interface RpycContainer {
  readonly format: "rpyc2" | "rpyc1";
  readonly slot: number | null;
  readonly payload: Buffer;
}

/**
 * Slot 2 holds the script after Ren'Py's static transforms, where dialogue
 * carries its translation identifier; slot 1 is the earlier form. Ren'Py
 * itself loads slot 2 first.
 */
export const readRpycContainer = (bytes: Buffer): RpycContainer => {
  if (bytes.toString("latin1", 0, HEADER.length) !== HEADER) {
    if (bytes[0] !== 0x78) fail("Not a compiled Ren'Py script (.rpyc).");
    return { format: "rpyc1", slot: null, payload: bytes };
  }
  const slots = new Map<number, { start: number; length: number }>();
  for (let at = HEADER.length; at + 12 <= bytes.length; at += 12) {
    const slot = bytes.readUInt32LE(at);
    if (slot === 0) break;
    const start = bytes.readUInt32LE(at + 4);
    const length = bytes.readUInt32LE(at + 8);
    if (start + length > bytes.length)
      fail(`Slot ${String(slot)} lies outside the file.`);
    slots.set(slot, { start, length });
  }
  const slot = slots.has(2)
    ? 2
    : slots.has(1)
      ? 1
      : fail("The .rpyc has no script slot.");
  const { start, length } = slots.get(slot) ?? { start: 0, length: 0 };
  return {
    format: "rpyc2",
    slot,
    payload: bytes.subarray(start, start + length),
  };
};

export interface LabelInfo {
  readonly name: string;
  readonly file: string | null;
  readonly line: number | null;
  statements: number;
  dialogue: number;
  menus: number;
  readonly jumps: string[];
  readonly calls: string[];
}

export interface SayInfo {
  readonly label: string | null;
  readonly file: string | null;
  readonly line: number | null;
  readonly who: string | null;
  readonly what: string;
  readonly identifier: string | null;
  readonly language: string | null;
}

export interface MenuInfo {
  readonly label: string | null;
  readonly file: string | null;
  readonly line: number | null;
  readonly caption: string | null;
  readonly choices: {
    readonly text: string;
    readonly condition: string | null;
    readonly jumps: readonly string[];
    readonly calls: readonly string[];
  }[];
}

export interface DefinitionInfo {
  readonly kind:
    | "define"
    | "default"
    | "image"
    | "screen"
    | "transform"
    | "style";
  readonly name: string;
  readonly store: string | null;
  readonly value: string | null;
  readonly file: string | null;
  readonly line: number | null;
}

export interface TranslationInfo {
  readonly kind: "string" | "block";
  readonly language: string | null;
  readonly identifier: string | null;
  readonly old: string | null;
  readonly new: string | null;
  readonly file: string | null;
  readonly line: number | null;
}

export interface RenpyScript {
  readonly container: RpycContainer;
  readonly scriptVersion: number | null;
  readonly files: readonly string[];
  readonly kinds: ReadonlyMap<string, number>;
  readonly labels: readonly LabelInfo[];
  readonly dialogue: readonly SayInfo[];
  readonly menus: readonly MenuInfo[];
  readonly definitions: readonly DefinitionInfo[];
  readonly translations: readonly TranslationInfo[];
}

const field = (node: PickleObject, name: string): PickleValue | undefined =>
  node.fields.get(name);

/** Source text of a PyExpr record, a PyCode record or a plain string. */
const sourceOf = (value: PickleValue | undefined): string | null => {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (value instanceof PickleObject) {
    if (value.type.name === "PyExpr") return sourceOf(value.args[0]);
    if (value.type.name === "PyCode") {
      const state = value.state;
      return Array.isArray(state)
        ? sourceOf(state[1] as PickleValue)
        : sourceOf(field(value, "source"));
    }
  }
  return null;
};

const text = (value: PickleValue | undefined): string | null =>
  typeof value === "string" ? value : sourceOf(value);

const number = (value: PickleValue | undefined): number | null =>
  typeof value === "bigint" ? Number(value) : null;

const list = (value: PickleValue | undefined): readonly PickleValue[] =>
  Array.isArray(value)
    ? (value as readonly PickleValue[])
    : value instanceof PickleObject
      ? value.items
      : [];

interface Context {
  readonly label: LabelInfo | null;
  readonly language: string | null;
  readonly identifier: string | null;
}

/** Walk Ren'Py's AST blocks, collecting the parts a modder or translator reads. */
class ScriptWalker {
  readonly files = new Set<string>();
  readonly kinds = new Map<string, number>();
  readonly labels: LabelInfo[] = [];
  readonly dialogue: SayInfo[] = [];
  readonly menus: MenuInfo[] = [];
  readonly definitions: DefinitionInfo[] = [];
  readonly translations: TranslationInfo[] = [];
  private readonly visited = new Set<PickleObject>();

  block(nodes: PickleValue | undefined, context: Context): void {
    for (const node of list(nodes)) this.node(node, context);
  }

  /** Jump and call targets directly inside a block, as a menu choice runs them. */
  private targets(
    nodes: PickleValue | undefined,
    kind: "Jump" | "Call",
  ): string[] {
    return list(nodes)
      .filter(
        (node): node is PickleObject =>
          node instanceof PickleObject && node.type.name === kind,
      )
      .map(
        (node) => text(field(node, kind === "Jump" ? "target" : "label")) ?? "",
      );
  }

  private where(node: PickleObject) {
    const file = text(field(node, "filename"));
    if (file !== null) this.files.add(file);
    return { file, line: number(field(node, "linenumber")) };
  }

  private say(node: PickleObject, context: Context): void {
    this.dialogue.push({
      label: context.label?.name ?? null,
      ...this.where(node),
      who: text(field(node, "who")),
      what: text(field(node, "what")) ?? "",
      identifier: text(field(node, "identifier")) ?? context.identifier,
      language: text(field(node, "language")) ?? context.language,
    });
    if (context.label !== null) context.label.dialogue += 1;
  }

  private menu(node: PickleObject, context: Context): void {
    const items = list(field(node, "items")).map((item) => list(item));
    this.menus.push({
      label: context.label?.name ?? null,
      ...this.where(node),
      caption: text(
        items.find((item) => item[2] === null || item[2] === undefined)?.[0],
      ),
      choices: items
        .filter((item) => item[2] !== null && item[2] !== undefined)
        .map((item) => ({
          text: text(item[0]) ?? "",
          condition: text(item[1]),
          jumps: this.targets(item[2], "Jump"),
          calls: this.targets(item[2], "Call"),
        })),
    });
    if (context.label !== null) context.label.menus += 1;
    for (const item of items) this.block(item[2], context);
  }

  private definition(
    node: PickleObject,
    kind: DefinitionInfo["kind"],
    name: string | null,
    value: string | null,
  ): void {
    this.definitions.push({
      kind,
      name: name ?? "",
      store: text(field(node, "store")),
      value,
      ...this.where(node),
    });
  }

  private label(node: PickleObject, context: Context): void {
    const info: LabelInfo = {
      name: text(field(node, "_name") ?? field(node, "name")) ?? "",
      ...this.where(node),
      statements: 0,
      dialogue: 0,
      menus: 0,
      jumps: [],
      calls: [],
    };
    this.labels.push(info);
    this.block(field(node, "block"), { ...context, label: info });
  }

  private flow(node: PickleObject, kind: string, context: Context): void {
    const label = context.label;
    if (label === null) return;
    const expression = field(node, "expression") === true;
    if (kind === "Jump") {
      const target = text(field(node, "target")) ?? "";
      label.jumps.push(expression ? `expression ${target}` : target);
    } else {
      const target = text(field(node, "label")) ?? "";
      label.calls.push(expression ? `expression ${target}` : target);
    }
  }

  private translate(node: PickleObject, context: Context): void {
    const language = text(field(node, "language"));
    const identifier = text(field(node, "identifier"));
    if (language !== null)
      this.translations.push({
        kind: "block",
        language,
        identifier,
        old: null,
        new: null,
        ...this.where(node),
      });
    this.block(field(node, "block"), { ...context, language, identifier });
  }

  private readonly handlers: Readonly<
    Record<string, (node: PickleObject, context: Context) => void>
  > = {
    Label: (node, context) => this.label(node, context),
    Say: (node, context) => this.say(node, context),
    TranslateSay: (node, context) => this.say(node, context),
    Menu: (node, context) => this.menu(node, context),
    Jump: (node, context) => this.flow(node, "Jump", context),
    Call: (node, context) => this.flow(node, "Call", context),
    If: (node, context) => {
      for (const entry of list(field(node, "entries")))
        this.block(list(entry)[1], context);
    },
    Translate: (node, context) => this.translate(node, context),
    TranslateString: (node) =>
      this.translations.push({
        kind: "string",
        language: text(field(node, "language")),
        identifier: null,
        old: text(field(node, "old")),
        new: text(field(node, "new")),
        ...this.where(node),
      }),
    Define: (node) =>
      this.definition(
        node,
        "define",
        text(field(node, "varname")),
        sourceOf(field(node, "code")),
      ),
    Default: (node) =>
      this.definition(
        node,
        "default",
        text(field(node, "varname")),
        sourceOf(field(node, "code")),
      ),
    Image: (node) =>
      this.definition(
        node,
        "image",
        list(field(node, "imgname"))
          .map((part) => text(part) ?? "")
          .join(" "),
        sourceOf(field(node, "code")) ??
          (field(node, "atl") === undefined ? null : "ATL"),
      ),
    Transform: (node) =>
      this.definition(node, "transform", text(field(node, "varname")), null),
    Style: (node) =>
      this.definition(node, "style", text(field(node, "style_name")), null),
    Screen: (node) => {
      const screen = field(node, "screen");
      this.definition(
        node,
        "screen",
        screen instanceof PickleObject ? text(field(screen, "name")) : null,
        null,
      );
    },
  };

  node(value: PickleValue, context: Context): void {
    if (!(value instanceof PickleObject) || this.visited.has(value)) return;
    this.visited.add(value);
    const kind = value.type.name;
    if (value.type.module !== "renpy.ast") return;
    this.kinds.set(kind, (this.kinds.get(kind) ?? 0) + 1);
    if (context.label !== null && kind !== "Label")
      context.label.statements += 1;
    this.where(value);
    const handle = this.handlers[kind];
    if (handle !== undefined) handle(value, context);
    // Init, While, TranslateBlock and similar nodes hold nested statements.
    if (handle === undefined || kind === "Say" || kind === "TranslateSay") {
      this.block(field(value, "block"), context);
      this.block(field(value, "code_block"), context);
    }
  }
}

/** Decode a .rpyc and summarise labels, dialogue, menus, definitions and translations. */
export const readRenpyScript = (bytes: Buffer): RenpyScript => {
  const container = readRpycContainer(bytes);
  let pickle: Buffer;
  try {
    pickle = inflateSync(container.payload, {
      maxOutputLength: MAX_SCRIPT_BYTES,
    });
  } catch (cause: unknown) {
    return fail(
      `The script data does not inflate: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  let decoded: PickleValue;
  try {
    decoded = decodeSafePickle(pickle, {
      objects: allowedClass,
      label: "Script pickle",
    });
  } catch (cause: unknown) {
    if (cause instanceof GameArchiveError) return fail(cause.message);
    throw cause;
  }
  const [meta, statements] = Array.isArray(decoded)
    ? (decoded as readonly PickleValue[])
    : fail("The script pickle is not a (data, statements) pair.");
  if (!Array.isArray(statements)) fail("The script has no statement list.");
  const walker = new ScriptWalker();
  walker.block(statements ?? [], {
    label: null,
    language: null,
    identifier: null,
  });
  return {
    container,
    scriptVersion: meta instanceof Map ? number(meta.get("version")) : null,
    files: [...walker.files],
    kinds: walker.kinds,
    labels: walker.labels,
    dialogue: walker.dialogue,
    menus: walker.menus,
    definitions: walker.definitions,
    translations: walker.translations,
  };
};
