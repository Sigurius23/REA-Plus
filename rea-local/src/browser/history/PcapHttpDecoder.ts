import type { UnknownObject } from "./PcapCaptureTypes.js";

const CREDENTIAL_HEADER =
  /^[\t ]*(?:authorization|proxy-authorization|cookie|set-cookie)[\t ]*(?::|$)/iu;
const URL_HEADERS = new Set(["location", "referer", "origin"]);
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const HEADER_NAME = new RegExp(`^${TOKEN}$`, "u");
const REQUEST_LINE = new RegExp(
  `^(${TOKEN}) ([^ \\r\\n]+) HTTP/(\\d)\\.(\\d)\\r\\n`,
  "u",
);
const STATUS_LINE = /^HTTP\/(\d)\.(\d) (\d{3})(?: ([^\r\n]*))?\r\n/u;
const USERINFO = /^((?:[a-z][a-z0-9+.-]*:)?\/\/)([^/?#]*@)/iu;

/** Decoded HTTP head plus RFC 6901 pointers whose credentials were removed. */
export interface HttpDecode {
  readonly reported: UnknownObject;
  readonly credentialPointers: readonly string[];
}

/** Recognize an HTTP/1.x request or status line at the start of a TCP payload. */
export const isHttp1Start = (payload: Buffer): boolean => {
  const head = payload.subarray(0, 256).toString("latin1");
  return REQUEST_LINE.test(head) || STATUS_LINE.test(head);
};

/**
 * Decode the HTTP/1.x message head that starts this segment, keeping header
 * octets byte-for-byte as latin1 text. Credential header values (including a
 * credential line cut at the segment end) are removed, and URL userinfo is
 * stripped from the request target and Location/Referer/Origin values.
 */
export const decodeHttp1Head = (
  payload: Buffer,
  pointer: string,
): HttpDecode => {
  const text = payload.toString("latin1");
  const end = text.indexOf("\r\n\r\n");
  const head = end === -1 ? text : text.slice(0, end + 2);
  const request = REQUEST_LINE.exec(head);
  const status = request === null ? STATUS_LINE.exec(head) : null;
  const startLine = request ?? status;
  if (startLine === null)
    return {
      reported: { protocol: "http/1", decode_status: "no-start-line" },
      credentialPointers: [],
    };
  const credentialPointers: string[] = [];
  const target =
    request === null
      ? undefined
      : withoutUserinfo(
          request[2] ?? "",
          `${pointer}/target`,
          credentialPointers,
        );
  const fields = headerFields(
    head.slice(startLine[0].length),
    end !== -1,
    pointer,
    credentialPointers,
  );
  return {
    reported: {
      protocol:
        request === null
          ? `http/${status?.[1] ?? ""}.${status?.[2] ?? ""}`
          : `http/${request[3] ?? ""}.${request[4] ?? ""}`,
      ...(request === null
        ? {
            kind: "response",
            status: Number(status?.[3]),
            reason: status?.[4] ?? "",
          }
        : { kind: "request", method: request[1], target }),
      ...fields,
      head_complete: end !== -1,
      body_bytes_in_segment: end === -1 ? 0 : payload.length - (end + 4),
    },
    credentialPointers,
  };
};

const headerFields = (
  block: string,
  complete: boolean,
  pointer: string,
  credentialPointers: string[],
): UnknownObject => {
  const lines = block.split("\r\n");
  // A complete head ends with an empty line; a partial head keeps its last line.
  const partial = complete ? undefined : lines.pop();
  if (complete) lines.pop();
  const headers: UnknownObject[] = [];
  const malformed: (string | null)[] = [];
  for (const line of lines) {
    const separator = line.indexOf(":");
    const name = separator > 0 ? line.slice(0, separator) : "";
    if (!HEADER_NAME.test(name)) {
      malformed.push(
        credentialLine(
          line,
          `${pointer}/malformed_lines/${malformed.length}`,
          credentialPointers,
        ),
      );
      continue;
    }
    const valuePointer = `${pointer}/headers/${headers.length}/value`;
    const raw = line.slice(separator + 1).trim();
    headers.push({
      name,
      value: CREDENTIAL_HEADER.test(line)
        ? credential(valuePointer, credentialPointers)
        : URL_HEADERS.has(name.toLowerCase())
          ? withoutUserinfo(raw, valuePointer, credentialPointers)
          : raw,
    });
  }
  return {
    headers,
    ...(malformed.length === 0 ? {} : { malformed_lines: malformed }),
    ...(partial === undefined || partial.length === 0
      ? {}
      : {
          partial_line: credentialLine(
            partial,
            `${pointer}/partial_line`,
            credentialPointers,
          ),
        }),
  };
};

const credential = (pointer: string, credentialPointers: string[]): null => {
  credentialPointers.push(pointer);
  return null;
};

const credentialLine = (
  line: string,
  pointer: string,
  credentialPointers: string[],
): string | null =>
  CREDENTIAL_HEADER.test(line) ? credential(pointer, credentialPointers) : line;

const withoutUserinfo = (
  value: string,
  pointer: string,
  credentialPointers: string[],
): string => {
  const match = USERINFO.exec(value);
  if (match === null) return value;
  credentialPointers.push(pointer);
  return `${match[1] ?? ""}${value.slice(match[0].length)}`;
};
