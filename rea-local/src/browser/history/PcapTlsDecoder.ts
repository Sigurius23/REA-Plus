import type { UnknownObject } from "./PcapCaptureTypes.js";

const HANDSHAKE = 0x16;
const CLIENT_HELLO = 1;
const SERVER_HELLO = 2;
const SERVER_NAME = 0;
const ALPN = 16;
const SUPPORTED_VERSIONS = 43;

/** Recognize a TLS handshake record at the start of a TCP segment payload. */
export const isTlsHandshake = (payload: Buffer): boolean =>
  payload.length >= 6 &&
  payload[0] === HANDSHAKE &&
  payload[1] === 3 &&
  (payload[2] ?? 0xff) <= 4 &&
  (payload[5] === CLIENT_HELLO || payload[5] === SERVER_HELLO);

/**
 * Decode the cleartext hello at the start of one TLS record (RFC 8446 4.1).
 * Only bytes inside this segment are read; a hello split across segments
 * reports what was observed with `complete: false`.
 */
export const decodeTlsHello = (payload: Buffer): UnknownObject => {
  const recordBytes = payload.readUInt16BE(3);
  const handshakeType = payload[5] ?? 0;
  const record = payload.subarray(5, Math.min(payload.length, 5 + recordBytes));
  const reader = new Reader(record);
  const result: UnknownObject = {
    protocol: "tls",
    record_version: versionName(payload.readUInt16BE(1)),
    record_bytes: recordBytes,
    handshake: handshakeType === CLIENT_HELLO ? "client_hello" : "server_hello",
  };
  try {
    reader.skip(1);
    const handshakeBytes = reader.u24();
    result.handshake_bytes = handshakeBytes;
    result.legacy_version = versionName(reader.u16());
    reader.skip(32);
    reader.skip(reader.u8());
    if (handshakeType === CLIENT_HELLO) {
      result.cipher_suite_count = reader.u16() / 2;
      reader.skip(Number(result.cipher_suite_count) * 2);
      reader.skip(reader.u8());
    } else {
      result.cipher_suite = hex16(reader.u16());
      reader.skip(1);
    }
    Object.assign(result, extensions(reader, handshakeType));
    result.complete = 4 + handshakeBytes <= record.length;
  } catch (cause: unknown) {
    if (!(cause instanceof RangeError)) throw cause;
    result.complete = false;
    result.decode_status = "hello-spans-segments";
  }
  return result;
};

const extensions = (reader: Reader, handshakeType: number): UnknownObject => {
  if (reader.remaining() === 0) return { extensions: [] };
  const end = reader.offset + 2 + reader.peekU16();
  reader.skip(2);
  const types: number[] = [];
  const found: UnknownObject = {};
  while (reader.offset < end) {
    const type = reader.u16();
    const body = new Reader(reader.take(reader.u16()));
    types.push(type);
    if (type === SERVER_NAME && handshakeType === CLIENT_HELLO)
      found.server_names = serverNames(body);
    else if (type === ALPN) found.alpn = alpn(body);
    else if (type === SUPPORTED_VERSIONS)
      found.supported_versions =
        handshakeType === CLIENT_HELLO
          ? versions(body)
          : [versionName(body.u16())];
  }
  return { extensions: types, ...found };
};

const serverNames = (body: Reader): UnknownObject[] => {
  const names: UnknownObject[] = [];
  const list = new Reader(body.take(body.u16()));
  while (list.remaining() > 0) {
    const nameType = list.u8();
    const name = list.take(list.u16());
    // host_name is ASCII by definition; latin1 keeps every byte visible.
    names.push({ name_type: nameType, name: name.toString("latin1") });
  }
  return names;
};

const alpn = (body: Reader): string[] => {
  const protocols: string[] = [];
  const list = new Reader(body.take(body.u16()));
  while (list.remaining() > 0)
    protocols.push(list.take(list.u8()).toString("latin1"));
  return protocols;
};

const versions = (body: Reader): string[] => {
  const result: string[] = [];
  const list = new Reader(body.take(body.u8()));
  while (list.remaining() >= 2) result.push(versionName(list.u16()));
  return result;
};

const versionName = (value: number): string =>
  value === 0x0304
    ? "TLS 1.3"
    : value === 0x0303
      ? "TLS 1.2"
      : value === 0x0302
        ? "TLS 1.1"
        : value === 0x0301
          ? "TLS 1.0"
          : value === 0x0300
            ? "SSL 3.0"
            : hex16(value);

const hex16 = (value: number): string =>
  `0x${value.toString(16).padStart(4, "0")}`;

/** Bounds-checked big-endian reader; RangeError marks bytes beyond the segment. */
class Reader {
  offset = 0;
  constructor(private readonly bytes: Buffer) {}

  remaining(): number {
    return this.bytes.length - this.offset;
  }

  skip(count: number): void {
    this.take(count);
  }

  take(count: number): Buffer {
    if (count > this.remaining()) throw new RangeError("TLS field truncated");
    const value = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return value;
  }

  u8(): number {
    return this.take(1).readUInt8(0);
  }

  u16(): number {
    return this.take(2).readUInt16BE(0);
  }

  peekU16(): number {
    if (this.remaining() < 2) throw new RangeError("TLS field truncated");
    return this.bytes.readUInt16BE(this.offset);
  }

  u24(): number {
    return this.take(3).readUIntBE(0, 3);
  }
}
