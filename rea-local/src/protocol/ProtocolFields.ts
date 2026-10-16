import { CHECKSUMS, type Checksum } from "./ProtocolChecksums.js";
import type { Message } from "./ProtocolMessages.js";

/**
 * Field inference over messages of one format, by byte offset: length
 * fields that track the message size, counters that step through the
 * capture, checksums of the rest of the message, timestamps near the
 * capture's clock, constants, text, floats, small enums, unique ids, and a
 * variable tail.
 */

export type FieldKind =
  | "type"
  | "constant"
  | "length"
  | "counter"
  | "checksum"
  | "timestamp"
  | "float"
  | "text"
  | "enum"
  | "id"
  | "bytes"
  | "variable";

export interface InferredField {
  readonly offset: number;
  /** Fields at the end of messages that differ in length count from the end. */
  readonly from: "start" | "end";
  readonly length: number | null;
  readonly kind: FieldKind;
  readonly encoding: string | null;
  readonly detail: string | null;
  readonly distinct: number;
  readonly samples: readonly string[];
}

type Endian = "le" | "be";
interface Slot {
  readonly offset: number;
  readonly width: 1 | 2 | 4;
  readonly endian: Endian;
}

const MAX_FIXED = 512;
const DAY = 86_400;
/** Seconds from 1900, NTP's epoch, to 1970. */
const NTP_EPOCH = 2_208_988_800;

const read = (data: Buffer, slot: Slot): number => {
  const { offset, width, endian } = slot;
  if (width === 1) return data[offset] ?? 0;
  if (width === 2)
    return endian === "le"
      ? data.readUInt16LE(offset)
      : data.readUInt16BE(offset);
  return endian === "le"
    ? data.readUInt32LE(offset)
    : data.readUInt32BE(offset);
};

const encoding = (slot: Slot): string =>
  slot.width === 1 ? "u8" : `u${String(slot.width * 8)}${slot.endian}`;

const slots = (offset: number, limit: number): Slot[] =>
  ([4, 2, 1] as const)
    .filter((width) => offset + width <= limit)
    .flatMap((width) =>
      (width === 1 ? (["le"] as const) : (["le", "be"] as const)).map(
        (endian) => ({ offset, width, endian }),
      ),
    );

/** A 4-byte reading is only kept when its upper half carries data somewhere; otherwise the 2-byte reading is the field. */
const upperUsed = (messages: readonly Message[], slot: Slot): boolean =>
  slot.width !== 4 || messages.some(({ data }) => read(data, slot) > 0xffff);

/** The byte holding the most significant bits of a reading. */
const topByte = (slot: Slot): number =>
  slot.endian === "le" ? slot.offset + slot.width - 1 : slot.offset;

/**
 * When the top byte never varies, a little-endian field at one offset and a
 * big-endian one at the offset before read the same; keep only the byte
 * order the capture's unambiguous fields use.
 */
const settled = (
  messages: readonly Message[],
  slot: Slot,
  order: Endian,
): boolean =>
  slot.width === 1 ||
  slot.endian === order ||
  new Set(messages.map(({ data }) => data[topByte(slot)])).size > 1;

const distinct = (values: readonly (number | string)[]): number =>
  new Set(values).size;

const samples = (values: readonly (number | string)[]): string[] =>
  [...new Set(values)].slice(0, 4).map(String);

const numericField = (
  messages: readonly Message[],
  slot: Slot,
  kind: FieldKind,
  detail: string,
): InferredField => {
  const values = messages.map(({ data }) => read(data, slot));
  return {
    offset: slot.offset,
    from: "start",
    length: slot.width,
    kind,
    encoding: encoding(slot),
    detail,
    distinct: distinct(values),
    samples: samples(values),
  };
};

/** The adjustment c in value + c = message length, when one c fits every message. */
const lengthAdjust = (
  messages: readonly Message[],
  slot: Slot,
): number | null => {
  const first = messages[0];
  if (first === undefined) return null;
  const c = first.data.length - read(first.data, slot);
  return Math.abs(c) <= 64 &&
    messages.every(({ data }) => data.length - read(data, slot) === c)
    ? c
    : null;
};

/** value + c = message length, for one c across messages of several lengths. */
const lengthAt = (
  messages: readonly Message[],
  offset: number,
  limit: number,
  order: Endian,
): InferredField | null => {
  if (distinct(messages.map(({ data }) => data.length)) < 2) return null;
  for (const slot of slots(offset, limit)) {
    const c = lengthAdjust(messages, slot);
    if (
      c === null ||
      !upperUsed(messages, slot) ||
      !settled(messages, slot, order)
    )
      continue;
    const end = slot.offset + slot.width;
    const detail =
      c === end
        ? "bytes after this field"
        : c === 0
          ? "message length"
          : `message length ${c > 0 ? "-" : "+"} ${String(Math.abs(c))}`;
    return numericField(messages, slot, "length", detail);
  }
  return null;
};

/** Messages of each flow and direction in capture order. */
const flows = (messages: readonly Message[]): Message[][] => {
  const groups = new Map<string, Message[]>();
  for (const message of messages) {
    const key = `${message.flow}|${message.direction ?? ""}`;
    groups.set(key, [...(groups.get(key) ?? []), message]);
  }
  return [...groups.values()];
};

/** The step a slot's values take between consecutive messages of a flow at least 80% of the time, or null. */
const counterStep = (
  messages: readonly Message[],
  ordered: readonly Message[][],
  slot: Slot,
): number | null => {
  const modulus = 2 ** (slot.width * 8);
  const steps = new Map<number, number>();
  let pairs = 0;
  for (const group of ordered)
    for (let at = 1; at < group.length; at += 1) {
      const step =
        (read(group[at]?.data ?? Buffer.alloc(8), slot) -
          read(group[at - 1]?.data ?? Buffer.alloc(8), slot) +
          modulus) %
        modulus;
      steps.set(step, (steps.get(step) ?? 0) + 1);
      pairs += 1;
    }
  const [step, count] = [...steps]
    .filter(([value]) => value >= 1 && value <= 16)
    .sort((a, b) => b[1] - a[1])[0] ?? [0, 0];
  return pairs >= 2 &&
    count >= pairs * 0.8 &&
    distinct(messages.map(({ data }) => read(data, slot))) >= 3
    ? step
    : null;
};

/**
 * A 32-bit counter's upper half is zero, or changes as it counts; an upper
 * half that is a non-zero constant in each flow is a field of its own.
 */
const counterWidthFits = (
  ordered: readonly Message[][],
  slot: Slot,
): boolean => {
  if (slot.width !== 4) return true;
  const upper = (data: Buffer) => read(data, slot) >>> 16;
  const lower = (data: Buffer) => read(data, slot) & 0xffff;
  let carries = 0;
  for (const group of ordered)
    for (let at = 1; at < group.length; at += 1) {
      const before = group[at - 1]?.data ?? Buffer.alloc(8);
      const after = group[at]?.data ?? Buffer.alloc(8);
      if (upper(before) === upper(after)) continue;
      // The upper half may only change when the lower half wraps.
      if (lower(after) >= lower(before)) return false;
      carries += 1;
    }
  return (
    carries > 0 ||
    ordered.every((group) => group.every(({ data }) => upper(data) === 0))
  );
};

/** Whether a field's values rise between consecutive messages of each flow, with at least one pair to see it. */
const rises = (ordered: readonly Message[][], slot: Slot): boolean => {
  const modulus = 2 ** (slot.width * 8);
  let pairs = 0;
  for (const group of ordered)
    for (let at = 1; at < group.length; at += 1) {
      const step =
        (read(group[at]?.data ?? Buffer.alloc(8), slot) -
          read(group[at - 1]?.data ?? Buffer.alloc(8), slot) +
          modulus) %
        modulus;
      if (step === 0 || step >= modulus / 2) return false;
      pairs += 1;
    }
  return pairs > 0;
};

/** Values that step by one small amount between consecutive messages of a flow. */
/** Messages of a format with their flows and the capture's byte order. */
interface Sample {
  readonly messages: readonly Message[];
  readonly ordered: readonly Message[][];
  readonly order: Endian;
}

const counterAt = (
  { messages, ordered, order }: Sample,
  offset: number,
  limit: number,
): InferredField | null => {
  // Sequence numbers are usually 32-bit even while small, so the wide reading is tried first.
  for (const slot of slots(offset, limit)) {
    if (!settled(messages, slot, order) || !counterWidthFits(ordered, slot))
      continue;
    const step = counterStep(messages, ordered, slot);
    if (step !== null)
      return numericField(
        messages,
        slot,
        "counter",
        `increments by ${String(step)}`,
      );
  }
  return null;
};

/** Seconds, milliseconds or microseconds since the epoch, within a day of the capture's clock. */
const timestampAt = (
  messages: readonly Message[],
  offset: number,
  limit: number,
): InferredField | null => {
  if (messages.some(({ time }) => time === null)) return null;
  for (const endian of ["le", "be"] as const) {
    if (offset + 4 <= limit) {
      const slot: Slot = { offset, width: 4, endian };
      if (
        messages.every(
          ({ data, time }) => Math.abs(read(data, slot) - (time ?? 0)) < DAY,
        )
      )
        return numericField(messages, slot, "timestamp", "seconds since 1970");
      if (
        messages.every(
          ({ data, time }) =>
            Math.abs(read(data, slot) - NTP_EPOCH - (time ?? 0)) < DAY,
        )
      )
        return numericField(
          messages,
          slot,
          "timestamp",
          "seconds since 1900 (NTP)",
        );
    }
    if (offset + 8 > limit) continue;
    const big = (data: Buffer) =>
      Number(
        endian === "le"
          ? data.readBigUInt64LE(offset)
          : data.readBigUInt64BE(offset),
      );
    for (const [scale, unit] of [
      [1e3, "milliseconds"],
      [1e6, "microseconds"],
    ] as const)
      if (
        messages.every(
          ({ data, time }) => Math.abs(big(data) / scale - (time ?? 0)) < DAY,
        )
      ) {
        const values = messages.map(({ data }) => big(data));
        return {
          offset,
          from: "start",
          length: 8,
          kind: "timestamp",
          encoding: `u64${endian}`,
          detail: `${unit} since 1970`,
          distinct: distinct(values),
          samples: samples(values),
        };
      }
  }
  return null;
};

interface Coverage {
  readonly label: string;
  readonly bytes: (data: Buffer) => Buffer;
}

const write = (data: Buffer, slot: Slot): number => read(data, slot);

/** Whether the field holds the checksum of the coverage in every message; the first few reject most candidates. */
const checksumMatches = (
  messages: readonly Message[],
  checksum: Checksum,
  field: (data: Buffer) => number,
  coverage: Coverage,
): boolean => {
  const holds = ({ data }: Message) =>
    field(data) === checksum.compute(coverage.bytes(data));
  return (
    messages.length >= 3 &&
    messages.slice(0, 3).every(holds) &&
    distinct(messages.map(({ data }) => field(data))) >= 2 &&
    messages.every(holds)
  );
};

/** A checksum near the start: over the bytes after it, the bytes before it, or the whole message with it zeroed. */
const checksumAt = (
  messages: readonly Message[],
  offset: number,
  limit: number,
): InferredField | null => {
  for (const checksum of CHECKSUMS) {
    for (const endian of checksum.width === 1
      ? (["le"] as const)
      : (["le", "be"] as const)) {
      const slot: Slot = { offset, width: checksum.width, endian };
      if (offset + slot.width > limit) continue;
      const end = offset + slot.width;
      const shortest = Math.min(...messages.map(({ data }) => data.length));
      const starts = Array.from(
        { length: Math.max(0, Math.min(shortest, 48) - end + 1) },
        (_, step) => end + step,
      );
      const coverages: Coverage[] = [
        ...starts.map((start) => ({
          label: `bytes ${String(start)} to the end`,
          bytes: (data: Buffer) => data.subarray(start),
        })),
        ...(offset >= 2
          ? [
              {
                label: `bytes 0 to ${String(offset)}`,
                bytes: (data: Buffer) => data.subarray(0, offset),
              },
            ]
          : []),
        {
          label: "the whole message with this field zeroed",
          bytes: (data: Buffer) =>
            Buffer.concat([
              data.subarray(0, offset),
              Buffer.alloc(slot.width),
              data.subarray(end),
            ]),
        },
      ];
      const coverage = coverages.find((candidate) =>
        checksumMatches(
          messages,
          checksum,
          (data) => write(data, slot),
          candidate,
        ),
      );
      if (coverage !== undefined)
        return numericField(
          messages,
          slot,
          "checksum",
          `${checksum.name} of ${coverage.label}`,
        );
    }
  }
  return null;
};

/** A checksum in the last bytes, over everything from a header offset up to it. */
export const trailerChecksum = (
  messages: readonly Message[],
): InferredField | null => {
  const shortest = Math.min(...messages.map(({ data }) => data.length));
  for (const checksum of CHECKSUMS)
    for (const endian of checksum.width === 1
      ? (["le"] as const)
      : (["le", "be"] as const))
      for (
        let start = 0;
        start < Math.min(48, shortest - checksum.width);
        start += 1
      ) {
        const field = (data: Buffer) =>
          read(data, {
            offset: data.length - checksum.width,
            width: checksum.width,
            endian,
          });
        const coverage: Coverage = {
          label: `bytes ${String(start)} up to this field`,
          bytes: (data) => data.subarray(start, data.length - checksum.width),
        };
        if (!checksumMatches(messages, checksum, field, coverage)) continue;
        const values = messages.map(({ data }) => field(data));
        return {
          offset: checksum.width,
          from: "end",
          length: checksum.width,
          kind: "checksum",
          encoding:
            checksum.width === 1
              ? "u8"
              : `u${String(checksum.width * 8)}${endian}`,
          detail: `${checksum.name} of ${coverage.label}`,
          distinct: distinct(values),
          samples: samples(values),
        };
      }
  return null;
};

/**
 * The byte order of fields whose reading is unambiguous: lengths and
 * counters whose top byte varies. Network order wins a tie.
 */
const byteOrder = (
  messages: readonly Message[],
  ordered: readonly Message[][],
  limit: number,
): Endian => {
  let little = 0;
  let big = 0;
  for (let offset = 0; offset < limit; offset += 1)
    for (const slot of slots(offset, limit)) {
      if (
        slot.width === 1 ||
        new Set(messages.map(({ data }) => data[topByte(slot)])).size < 2
      )
        continue;
      const fits =
        (lengthAdjust(messages, slot) !== null &&
          distinct(messages.map(({ data }) => data.length)) > 1) ||
        counterStep(messages, ordered, slot) !== null;
      if (!fits) continue;
      if (slot.endian === "le") little += 1;
      else big += 1;
    }
  return little > big ? "le" : "be";
};

export {
  MAX_FIXED,
  byteOrder,
  encoding,
  flows,
  rises,
  lengthAdjust,
  lengthAt,
  counterAt,
  timestampAt,
  checksumAt,
  read,
  samples,
  distinct,
  type Endian,
  type Sample,
  type Slot,
};
