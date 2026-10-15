import { visit } from "jsonc-parser";
import { LosslessNumber } from "lossless-json";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";

export interface HarJsonVisitor {
  onObjectBegin?(pointer: string): void;
  onObjectProperty?(key: string, pointer: string): void;
  onObjectEnd?(pointer: string): void;
  onArrayBegin?(pointer: string): void;
  onArrayEnd?(pointer: string): void;
  onLiteralValue?(
    value: unknown,
    pointer: string,
    offset: number,
    length: number,
  ): void;
}

type ParserFrame =
  | {
      kind: "object";
      pointer: string;
      keys: Set<string>;
      pendingKey?: string;
    }
  | { kind: "array"; pointer: string; nextIndex: number };

/** Visit complete HAR JSON without constructing a document-sized syntax tree. */
export const visitHarJson = (text: string, visitor: HarJsonVisitor): void => {
  const frames: ParserFrame[] = [];
  let rootStarted = false;

  const beginValue = (): string => {
    const parent = frames.at(-1);
    if (parent === undefined) {
      if (rootStarted)
        throw new CaptureFormatError("format", "HAR is malformed JSON.");
      rootStarted = true;
      return "";
    }
    if (parent.kind === "array")
      return `${parent.pointer}/${parent.nextIndex++}`;
    if (parent.pendingKey === undefined)
      throw new TypeError("JSON visitor omitted an object property identity.");
    const pointer = capturePointer(parent.pointer, parent.pendingKey);
    delete parent.pendingKey;
    return pointer;
  };

  const checkDepth = (pointer: string, openingContainer: boolean): void => {
    const tooDeep = openingContainer
      ? frames.length >= WEB_NETWORK_CAPTURE_LIMITS.depth
      : frames.length > WEB_NETWORK_CAPTURE_LIMITS.depth;
    if (tooDeep)
      throw new CaptureFormatError(
        "input-limit",
        `HAR exceeds the ${WEB_NETWORK_CAPTURE_LIMITS.depth}-level complete-evidence nesting budget.`,
        pointer,
        { kind: "nesting", maximum: WEB_NETWORK_CAPTURE_LIMITS.depth },
      );
  };

  visit(
    text,
    {
      onObjectBegin: () => {
        const pointer = beginValue();
        checkDepth(pointer, true);
        frames.push({ kind: "object", pointer, keys: new Set() });
        visitor.onObjectBegin?.(pointer);
      },
      onObjectProperty: (key) => {
        const frame = frames.at(-1);
        if (frame?.kind !== "object")
          throw new TypeError(
            "JSON visitor emitted a property outside an object.",
          );
        if (frame.keys.has(key))
          throw new CaptureFormatError(
            "format",
            "HAR JSON contains duplicate object members.",
            capturePointer(frame.pointer, key),
          );
        if (frame.pendingKey !== undefined)
          throw new TypeError(
            "JSON visitor emitted consecutive object properties.",
          );
        frame.keys.add(key);
        frame.pendingKey = key;
        visitor.onObjectProperty?.(key, capturePointer(frame.pointer, key));
      },
      onObjectEnd: () => {
        const frame = frames.pop();
        if (frame?.kind !== "object")
          throw new TypeError("JSON visitor ended an unexpected object.");
        if (frame.pendingKey !== undefined)
          throw new CaptureFormatError(
            "format",
            "HAR is malformed JSON.",
            frame.pointer,
          );
        visitor.onObjectEnd?.(frame.pointer);
      },
      onArrayBegin: () => {
        const pointer = beginValue();
        checkDepth(pointer, true);
        frames.push({ kind: "array", pointer, nextIndex: 0 });
        visitor.onArrayBegin?.(pointer);
      },
      onArrayEnd: () => {
        const frame = frames.pop();
        if (frame?.kind !== "array")
          throw new TypeError("JSON visitor ended an unexpected array.");
        visitor.onArrayEnd?.(frame.pointer);
      },
      onLiteralValue: (value: unknown, offset, length) => {
        const pointer = beginValue();
        checkDepth(pointer, false);
        visitor.onLiteralValue?.(value, pointer, offset, length);
      },
      onError: () => {
        throw new CaptureFormatError("format", "HAR is malformed JSON.");
      },
    },
    {
      disallowComments: true,
      allowTrailingComma: false,
      allowEmptyContent: false,
    },
  );
  if (!rootStarted || frames.length !== 0)
    throw new CaptureFormatError("format", "HAR is malformed JSON.");
};

type ValueFrame =
  | {
      kind: "object";
      pointer: string;
      members: Map<string, unknown>;
      pendingKey?: string;
    }
  | { kind: "array"; pointer: string; items: unknown[] };

/** Materialize a complete JSON value while preserving exact numbers and prototype-named members. */
export const parseHarJson = (text: string): unknown => {
  const frames: ValueFrame[] = [];
  let result: unknown;
  let hasResult = false;
  const append = (value: unknown): void => {
    const parent = frames.at(-1);
    if (parent === undefined) {
      result = value;
      hasResult = true;
    } else if (parent.kind === "array") parent.items.push(value);
    else {
      if (parent.pendingKey === undefined)
        throw new TypeError(
          "JSON visitor omitted an object property identity.",
        );
      parent.members.set(parent.pendingKey, value);
      delete parent.pendingKey;
    }
  };
  visitHarJson(text, {
    onObjectBegin: (pointer) =>
      frames.push({ kind: "object", pointer, members: new Map() }),
    onObjectProperty: (key) => {
      const frame = frames.at(-1);
      if (frame?.kind !== "object")
        throw new TypeError(
          "JSON visitor emitted a property outside an object.",
        );
      frame.pendingKey = key;
    },
    onObjectEnd: () => {
      const frame = frames.pop();
      if (frame?.kind !== "object")
        throw new TypeError("JSON visitor ended an unexpected object.");
      append(Object.fromEntries(frame.members));
    },
    onArrayBegin: (pointer) =>
      frames.push({ kind: "array", pointer, items: [] }),
    onArrayEnd: () => {
      const frame = frames.pop();
      if (frame?.kind !== "array")
        throw new TypeError("JSON visitor ended an unexpected array.");
      append(frame.items);
    },
    onLiteralValue: (value, _pointer, offset, length) => {
      if (typeof value === "number")
        append(new LosslessNumber(text.slice(offset, offset + length)));
      else if (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "string"
      )
        append(value);
      else throw new TypeError("JSON visitor emitted an unsupported literal.");
    },
  });
  if (!hasResult)
    throw new CaptureFormatError("format", "HAR is malformed JSON.");
  return result;
};

const capturePointer = (parent: string, key: string): string =>
  `${parent}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`;
