import { ipv4Address, ipv6Address } from "./PcapCaptureBinary.js";
import type { UnknownObject } from "./PcapCaptureTypes.js";

/** Resource records decoded per section; header counts remain authoritative. */
const MAX_RECORDS_PER_SECTION = 64;
const MAX_RDATA_HEX_BYTES = 512;
const MAX_NAME_POINTERS = 32;

const RECORD_TYPES: Readonly<Record<number, string>> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  41: "OPT",
  64: "SVCB",
  65: "HTTPS",
  255: "ANY",
};

const RESPONSE_CODES: Readonly<Record<number, string>> = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
};

interface Cursor {
  readonly message: Buffer;
  offset: number;
}

/**
 * Decode one complete DNS message (RFC 1035) from a UDP payload, or from a TCP
 * segment carrying its two-byte length prefix. Names keep RFC 1035
 * presentation escapes, so non-printable label bytes are not lost.
 */
export const decodeDnsMessage = (
  payload: Buffer,
  transport: "tcp" | "udp",
): UnknownObject => {
  let message = payload;
  if (transport === "tcp") {
    if (payload.length < 2)
      return { protocol: "dns", transport, decode_status: "truncated-length" };
    const declared = payload.readUInt16BE(0);
    if (payload.length - 2 < declared)
      return {
        protocol: "dns",
        transport,
        declared_bytes: declared,
        decode_status: "message-spans-segments",
      };
    message = payload.subarray(2, 2 + declared);
  }
  if (message.length < 12)
    return { protocol: "dns", transport, decode_status: "truncated-header" };
  const flags = message.readUInt16BE(2);
  const counts = {
    questions: message.readUInt16BE(4),
    answers: message.readUInt16BE(6),
    authorities: message.readUInt16BE(8),
    additionals: message.readUInt16BE(10),
  };
  const header = {
    id: message.readUInt16BE(0),
    response: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 0xf,
    authoritative: (flags & 0x0400) !== 0,
    truncated: (flags & 0x0200) !== 0,
    recursion_desired: (flags & 0x0100) !== 0,
    recursion_available: (flags & 0x0080) !== 0,
    response_code: flags & 0xf,
    ...(RESPONSE_CODES[flags & 0xf] === undefined
      ? {}
      : { response_code_name: RESPONSE_CODES[flags & 0xf] }),
  };
  const cursor: Cursor = { message, offset: 12 };
  const questions: UnknownObject[] = [];
  const sections: Record<string, UnknownObject[]> = {
    answers: [],
    authorities: [],
    additionals: [],
  };
  let status = "decoded";
  try {
    for (let index = 0; index < counts.questions; index++) {
      const question = readQuestion(cursor);
      if (index < MAX_RECORDS_PER_SECTION) questions.push(question);
    }
    for (const section of ["answers", "authorities", "additionals"] as const)
      for (let index = 0; index < counts[section]; index++) {
        const record = readRecord(cursor);
        if (index < MAX_RECORDS_PER_SECTION) sections[section]?.push(record);
      }
    if (cursor.offset !== message.length) status = "trailing-bytes";
  } catch (cause: unknown) {
    if (!(cause instanceof DnsFormatError)) throw cause;
    status = cause.status;
  }
  return {
    protocol: "dns",
    transport,
    message_bytes: message.length,
    header,
    counts,
    questions,
    ...sections,
    records_limited:
      Math.max(
        counts.questions,
        counts.answers,
        counts.authorities,
        counts.additionals,
      ) > MAX_RECORDS_PER_SECTION,
    decode_status: status,
  };
};

class DnsFormatError extends Error {
  constructor(readonly status: string) {
    super(status);
  }
}

const need = (cursor: Cursor, bytes: number): void => {
  if (cursor.message.length - cursor.offset < bytes)
    throw new DnsFormatError("truncated-record");
};

const readQuestion = (cursor: Cursor): UnknownObject => {
  const name = readName(cursor);
  need(cursor, 4);
  const type = cursor.message.readUInt16BE(cursor.offset);
  const recordClass = cursor.message.readUInt16BE(cursor.offset + 2);
  cursor.offset += 4;
  return { name, ...recordType(type), class: recordClass };
};

const readRecord = (cursor: Cursor): UnknownObject => {
  const name = readName(cursor);
  need(cursor, 10);
  const { message } = cursor;
  const type = message.readUInt16BE(cursor.offset);
  const recordClass = message.readUInt16BE(cursor.offset + 2);
  const ttl = message.readUInt32BE(cursor.offset + 4);
  const length = message.readUInt16BE(cursor.offset + 8);
  cursor.offset += 10;
  need(cursor, length);
  const start = cursor.offset;
  cursor.offset += length;
  return {
    name,
    ...recordType(type),
    class: recordClass,
    ttl,
    data_bytes: length,
    ...recordData(message, type, start, length),
  };
};

const recordType = (type: number): UnknownObject =>
  RECORD_TYPES[type] === undefined
    ? { type }
    : { type, type_name: RECORD_TYPES[type] };

const recordData = (
  message: Buffer,
  type: number,
  start: number,
  length: number,
): UnknownObject => {
  const nested = (offset: number): string => {
    const cursor = { message, offset };
    const name = readName(cursor);
    if (cursor.offset > start + length)
      throw new DnsFormatError("malformed-record-data");
    return name;
  };
  if (type === 1 && length === 4)
    return { address: ipv4Address(message, start) };
  if (type === 28 && length === 16)
    return { address: ipv6Address(message, start) };
  if (type === 2 || type === 5 || type === 12) return { target: nested(start) };
  if (type === 15 && length >= 3)
    return {
      preference: message.readUInt16BE(start),
      exchange: nested(start + 2),
    };
  if (type === 16) return { texts: characterStrings(message, start, length) };
  const shown = Math.min(length, MAX_RDATA_HEX_BYTES);
  return {
    data_hex: message.subarray(start, start + shown).toString("hex"),
    data_hex_truncated: shown < length,
  };
};

const characterStrings = (
  message: Buffer,
  start: number,
  length: number,
): string[] => {
  const texts: string[] = [];
  let offset = start;
  while (offset < start + length) {
    const size = message[offset] ?? 0;
    if (offset + 1 + size > start + length)
      throw new DnsFormatError("malformed-record-data");
    texts.push(
      presentation(message.subarray(offset + 1, offset + 1 + size), true),
    );
    offset += 1 + size;
  }
  return texts;
};

/** Read a possibly compressed name, following at most 32 pointers. */
const readName = (cursor: Cursor): string => {
  const { message } = cursor;
  const labels: string[] = [];
  let offset = cursor.offset;
  let resume: number | undefined;
  let pointers = 0;
  let wireBytes = 0;
  for (;;) {
    const size = message[offset];
    if (size === undefined) throw new DnsFormatError("truncated-name");
    if ((size & 0xc0) === 0xc0) {
      const low = message[offset + 1];
      if (low === undefined) throw new DnsFormatError("truncated-name");
      resume ??= offset + 2;
      pointers += 1;
      if (pointers > MAX_NAME_POINTERS)
        throw new DnsFormatError("name-pointer-loop");
      offset = ((size & 0x3f) << 8) | low;
      continue;
    }
    if ((size & 0xc0) !== 0) throw new DnsFormatError("unsupported-label-type");
    if (size === 0) {
      cursor.offset = resume ?? offset + 1;
      return labels.length === 0 ? "." : labels.join(".");
    }
    wireBytes += size + 1;
    if (wireBytes > 255) throw new DnsFormatError("name-too-long");
    if (offset + 1 + size > message.length)
      throw new DnsFormatError("truncated-name");
    labels.push(presentation(message.subarray(offset + 1, offset + 1 + size)));
    offset += 1 + size;
  }
};

/**
 * RFC 1035 presentation text: printable ASCII is kept and `\\`, `"` and
 * other bytes use `\\DDD` escapes. Label dots are escaped; TXT strings keep
 * literal dots and spaces.
 */
const presentation = (bytes: Buffer, text = false): string =>
  [...bytes]
    .map((byte) =>
      byte === 0x5c || byte === 0x22 || (!text && byte === 0x2e)
        ? `\\${String.fromCharCode(byte)}`
        : (byte > 0x20 || (text && byte === 0x20)) && byte < 0x7f
          ? String.fromCharCode(byte)
          : `\\${byte.toString(10).padStart(3, "0")}`,
    )
    .join("");
