/** A decoded value tree shared by every blob format. */

export class BlobFormatError extends Error {
  override readonly name = "BlobFormatError";
}

/** A range, node or region chunk the input does not contain; reported against that field. */
export class BlobSelectionError extends Error {
  override readonly name = "BlobSelectionError";

  constructor(
    message: string,
    readonly field: "range_offset" | "range_length" | "node" | "region_chunk",
  ) {
    super(message);
  }
}

export interface BlobNode {
  /** Field number, map key, array index or tag name; null for the root. */
  readonly key: string | number | null;
  /** Format-specific type: message, varint, string, map, array, int, float... */
  readonly type: string;
  /** Scalar rendering; null for containers. */
  readonly value: string | null;
  /** Other readings of the same bytes: a varint as signed or zigzag, fixed32 as float... */
  readonly alternatives: Readonly<Record<string, string>>;
  /** Byte range in the decoded payload. */
  readonly offset: number;
  readonly length: number;
  readonly children: readonly BlobNode[];
}

export const node = (
  values: Pick<BlobNode, "key" | "type" | "offset" | "length"> &
    Partial<Pick<BlobNode, "value" | "alternatives" | "children">>,
): BlobNode => ({
  value: null,
  alternatives: {},
  children: [],
  ...values,
});

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Text when the bytes are UTF-8 without control characters other than tab, newline and carriage return. */
export const textOf = (bytes: Buffer): string | null => {
  let text: string;
  try {
    text = UTF8.decode(bytes);
  } catch {
    return null;
  }
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (
      (code < 0x20 && code !== 9 && code !== 10 && code !== 13) ||
      code === 0x7f
    )
      return null;
  }
  return text;
};

/** A leaf for raw bytes: text when it reads as text, hex otherwise. */
export const bytesNode = (
  key: BlobNode["key"],
  bytes: Buffer,
  offset: number,
): BlobNode => {
  const text = textOf(bytes);
  return node({
    key,
    type: text === null ? "bytes" : "string",
    value: text ?? bytes.toString("hex"),
    offset,
    length: bytes.length,
  });
};

/** Count nodes and depth for scoring candidates. */
export const measure = (
  root: BlobNode,
): { nodes: number; depth: number; strings: number } => {
  let nodes = 0;
  let depth = 0;
  let strings = 0;
  const visit = (current: BlobNode, level: number) => {
    nodes += 1;
    depth = Math.max(depth, level);
    if (current.type === "string") strings += 1;
    for (const child of current.children) visit(child, level + 1);
  };
  visit(root, 0);
  return { nodes, depth, strings };
};
