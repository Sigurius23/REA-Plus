import {
  byteOrder,
  rises,
  checksumAt,
  counterAt,
  distinct,
  flows,
  lengthAt,
  MAX_FIXED,
  samples,
  timestampAt,
  trailerChecksum,
  type InferredField,
} from "./ProtocolFields.js";
import type { Endian, Sample, Slot } from "./ProtocolFields.js";
import type { Framing } from "./ProtocolFraming.js";
import type { Message } from "./ProtocolMessages.js";

/**
 * The field layout of one message format. Semantic fields are placed
 * first (length, checksum, counter, timestamp), then constants and text,
 * floats, and the remaining varying bytes as enums, ids or plain bytes.
 */

const PRINTABLE = (byte: number) => byte >= 0x20 && byte < 0x7f;

/** The slot a numeric field was read from. */
const slotOf = (field: InferredField): Slot => ({
  offset: field.offset,
  width: (field.length ?? 1) as Slot["width"],
  endian: field.encoding?.endsWith("be") === true ? "be" : "le",
});

const column = (messages: readonly Message[], at: number): number[] =>
  messages.map(({ data }) => data[at] ?? 0);

const constantAt = (messages: readonly Message[], at: number): boolean =>
  distinct(column(messages, at)) === 1;

const slice = (
  messages: readonly Message[],
  offset: number,
  length: number,
): string[] =>
  messages.map(({ data }) =>
    data.subarray(offset, offset + length).toString("hex"),
  );

const run = (
  messages: readonly Message[],
  offset: number,
  length: number,
  kind: InferredField["kind"],
): InferredField => {
  const values =
    kind === "text" ||
    (kind === "constant" &&
      messages[0]?.data.subarray(offset, offset + length).every(PRINTABLE) ===
        true)
      ? messages.map(({ data }) =>
          JSON.stringify(
            data.subarray(offset, offset + length).toString("latin1"),
          ),
        )
      : slice(messages, offset, length);
  return {
    offset,
    from: "start",
    length,
    kind,
    encoding: kind === "text" ? "ascii" : null,
    detail: null,
    distinct: distinct(values),
    samples: samples(values),
  };
};

/** A float32 whose readings are all zero or of everyday magnitude, and not all whole numbers. */
const floatAt = (
  messages: readonly Message[],
  offset: number,
): InferredField | null => {
  for (const endian of ["le", "be"] as const) {
    const values = messages.map(({ data }) =>
      endian === "le" ? data.readFloatLE(offset) : data.readFloatBE(offset),
    );
    const plausible = values.every(
      (value) =>
        value === 0 ||
        (Number.isFinite(value) &&
          Math.abs(value) >= 1e-4 &&
          Math.abs(value) <= 1e7),
    );
    if (
      plausible &&
      values.some((value) => !Number.isInteger(value)) &&
      distinct(values) >= 2
    )
      return {
        offset,
        from: "start",
        length: 4,
        kind: "float",
        encoding: `f32${endian}`,
        detail: null,
        distinct: distinct(values),
        samples: samples(values.map((value) => Number(value.toPrecision(7)))),
      };
  }
  return null;
};

class Layout {
  readonly taken: boolean[];
  readonly fields: InferredField[] = [];

  constructor(
    readonly messages: readonly Message[],
    readonly limit: number,
  ) {
    this.taken = Array.from({ length: limit }, () => false);
  }

  free(offset: number, length: number): boolean {
    for (let at = offset; at < offset + length; at += 1)
      if (at >= this.limit || this.taken[at] === true) return false;
    return true;
  }

  place(field: InferredField | null): boolean {
    if (
      field === null ||
      field.from === "end" ||
      !this.free(field.offset, field.length ?? 0)
    )
      return false;
    for (
      let at = field.offset;
      at < field.offset + (field.length ?? 0);
      at += 1
    )
      this.taken[at] = true;
    this.fields.push(field);
    return true;
  }

  scan(detect: (offset: number) => InferredField | null): void {
    for (let offset = 0; offset < this.limit; offset += 1)
      if (this.free(offset, 1)) this.place(detect(offset));
  }

  /** Runs of free bytes that satisfy `test` column by column. */
  runs(
    test: (at: number) => boolean,
    minimum: number,
    kind: InferredField["kind"],
  ): void {
    for (let start = 0; start < this.limit; ) {
      let end = start;
      while (end < this.limit && this.free(end, 1) && test(end)) end += 1;
      if (end - start >= minimum)
        this.place(run(this.messages, start, end - start, kind));
      start = Math.max(end, start + 1);
    }
  }

  /** Whatever still varies: short low-cardinality runs are enums, unique runs ids, the rest bytes. */
  leftovers(): void {
    this.runs(() => true, 1, "bytes");
    const count = this.messages.length;
    for (const [index, field] of this.fields.entries()) {
      if (field.kind !== "bytes" || field.length === null) continue;
      const few = field.distinct <= Math.max(2, Math.min(16, count / 4));
      if (field.length <= 2 && count >= 4 && few)
        this.fields[index] = { ...field, kind: "enum" };
      else if (
        count >= 4 &&
        field.distinct === count &&
        field.length >= 2 &&
        field.length <= 16
      )
        this.fields[index] = { ...field, kind: "id" };
    }
  }
}

/** The bytes after the fixed region, less a trailer of `trim` bytes. */
const tail = (
  messages: readonly Message[],
  offset: number,
  trim: number,
): InferredField => {
  const part = (data: Buffer) => data.subarray(offset, data.length - trim);
  const bytes = Buffer.concat(messages.map(({ data }) => part(data)));
  const printable =
    bytes.length === 0 ? 0 : bytes.filter(PRINTABLE).length / bytes.length;
  const lengths = messages.map(({ data }) => part(data).length);
  const parts = messages.map(({ data }) => part(data).toString("hex"));
  return {
    offset,
    from: "start",
    length: null,
    kind: "variable",
    encoding: printable >= 0.9 ? "ascii" : null,
    detail: `${String(Math.min(...lengths))}-${String(Math.max(...lengths))} bytes, ${String(Math.round(printable * 100))}% printable`,
    distinct: distinct(parts),
    samples: samples(parts.map((hex) => hex.slice(0, 32))),
  };
};

const lengthHeader = (fields: readonly InferredField[]): number | null => {
  const header = fields
    .map(({ detail }) => /^message length - (\d+)$/u.exec(detail ?? "")?.[1])
    .find((value) => value !== undefined);
  return header === undefined ? null : Number(header);
};

export interface CaptureContext {
  readonly order: Endian;
  /** Counters in the header all messages share, which step across message types. */
  readonly counters: readonly InferredField[];
  /** Length fields in that header; their bytes are never a type key. */
  readonly lengths: readonly InferredField[];
}

/** Byte order and sequence counters, judged over every message before they are split by type. */
/** The framing's length prefix, as the length field it is. */
const prefixField = (
  messages: readonly Message[],
  framing: Framing,
): InferredField | null => {
  if (framing.kind !== "length_prefix") return null;
  const { offset, width, endian, adjust } = framing;
  const end = offset + width;
  const values = messages.map(({ data }) => data.length - adjust);
  return {
    offset,
    from: "start",
    length: width,
    kind: "length",
    encoding:
      width === 1
        ? "u8"
        : `u${String(width * 8)}${endian === "little" ? "le" : "be"}`,
    detail: `${adjust === end ? "bytes after this field" : adjust === 0 ? "message length" : `message length ${adjust > 0 ? "-" : "+"} ${String(Math.abs(adjust))}`}; frames the TCP stream`,
    distinct: new Set(values).size,
    samples: [...new Set(values)].slice(0, 4).map(String),
  };
};

export const captureContext = (
  messages: readonly Message[],
  framing: Framing = { kind: "datagrams" },
): CaptureContext => {
  const shortest = Math.min(
    MAX_FIXED,
    ...messages.map(({ data }) => data.length),
  );
  const ordered = flows(messages);
  const prefix = prefixField(messages, framing);
  // A multi-byte length prefix settles the byte order outright.
  const order =
    framing.kind === "length_prefix" && framing.width > 1
      ? framing.endian === "little"
        ? "le"
        : "be"
      : byteOrder(messages, ordered, Math.min(shortest, 64));
  const layout = new Layout(messages, Math.min(shortest, 64));
  if (prefix !== null) layout.place(prefix);
  layout.scan((offset) => lengthAt(messages, offset, layout.limit, order));
  const lengths = [...layout.fields];
  layout.scan((offset) =>
    counterAt({ messages, ordered, order }, offset, layout.limit),
  );
  return {
    order,
    counters: layout.fields.filter(({ kind }) => kind === "counter"),
    lengths,
  };
};

/** Text formats: the first word, then the rest of the line. */
export const textLayout = (
  messages: readonly Message[],
  key: FormatKey | null,
): InferredField[] => {
  const width = key?.width ?? 0;
  const fields: InferredField[] =
    key === null || width === 0
      ? []
      : [
          {
            offset: 0,
            from: "start",
            length: width,
            kind: "type",
            encoding: "ascii",
            detail: "the first word",
            distinct: 1,
            samples: [JSON.stringify(key.value)],
          },
        ];
  const rest = tail(messages, width, 0);
  return [
    ...fields,
    {
      ...rest,
      samples: [
        ...new Set(
          messages.map(({ data }) =>
            JSON.stringify(data.subarray(width).toString("latin1").trim()),
          ),
        ),
      ].slice(0, 4),
    },
  ];
};

/** The bytes that told this format from the others. */
export interface FormatKey {
  readonly offset: number;
  readonly width: number;
  readonly value: string;
}

/** The bytes every message of the format has at fixed offsets: up to the shortest, less a trailer. */
const fixedLimit = (
  messages: readonly Message[],
  trailer: InferredField | null,
): number => {
  const lengths = messages.map(({ data }) => data.length);
  const varied = distinct(lengths) > 1;
  // A trailer in messages of different sizes is not at a fixed offset; keep it out of the column analysis.
  return Math.max(
    0,
    Math.min(
      MAX_FIXED,
      Math.min(...lengths) -
        (varied && trailer !== null ? (trailer.length ?? 0) : 0),
    ),
  );
};

/** Fields known before the columns are read: the type key, the capture's counters and lengths. */
const knownFields = (
  layout: Layout,
  context: CaptureContext,
  key: FormatKey | null,
  ordered: readonly Message[][],
): void => {
  if (key !== null)
    layout.place({
      offset: key.offset,
      from: "start",
      length: key.width,
      kind: "type",
      encoding: null,
      detail: "tells this format from the others",
      distinct: 1,
      samples: [key.value],
    });
  // A capture-wide counter is this format's only where it rises here too.
  for (const counter of context.counters)
    if (counter.encoding !== null && rises(ordered, slotOf(counter)))
      layout.place(counter);
  for (const length of context.lengths) layout.place(length);
};

/** The fixed region's remaining fields, kind by kind in order of how much each claim says. */
const columns = (layout: Layout, sample: Sample): void => {
  const { messages } = sample;
  layout.scan((offset) =>
    offset < 32 ? checksumAt(messages, offset, layout.limit) : null,
  );
  layout.scan((offset) => counterAt(sample, offset, layout.limit));
  layout.scan((offset) => timestampAt(messages, offset, layout.limit));
  layout.runs((at) => constantAt(messages, at), 1, "constant");
  layout.runs((at) => column(messages, at).every(PRINTABLE), 3, "text");
  layout.scan((offset) =>
    layout.free(offset, 4) ? floatAt(messages, offset) : null,
  );
  layout.leftovers();
};

export const inferLayout = (
  messages: readonly Message[],
  context: CaptureContext,
  key: FormatKey | null = null,
): InferredField[] => {
  const lengths = messages.map(({ data }) => data.length);
  const varied = distinct(lengths) > 1;
  const trailer = trailerChecksum(messages);
  const ordered = flows(messages);
  const { order } = context;
  let layout = new Layout(messages, fixedLimit(messages, trailer));
  knownFields(layout, context, key, ordered);
  layout.scan((offset) => lengthAt(messages, offset, layout.limit, order));
  // A length that counts the bytes after a header says where the header ends.
  const header = varied ? lengthHeader(layout.fields) : null;
  if (header !== null && header < layout.limit) {
    const placed = layout.fields;
    layout = new Layout(messages, header);
    placed.forEach((field) => layout.place(field));
  }
  if (trailer !== null && !varied)
    layout.place({
      ...trailer,
      from: "start",
      offset: Math.min(...lengths) - (trailer.length ?? 0),
    });
  columns(layout, { messages, ordered, order });
  const fields = [...layout.fields].sort(
    (left, right) => left.offset - right.offset,
  );
  const trim = varied && trailer !== null ? (trailer.length ?? 0) : 0;
  if (Math.max(...lengths) - trim > layout.limit)
    fields.push(tail(messages, layout.limit, trim));
  if (trailer !== null && varied) fields.push(trailer);
  return fields;
};
