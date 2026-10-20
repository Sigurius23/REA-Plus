import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

import { DOMParser, onWarningStopParsing, type Element } from "@xmldom/xmldom";

import { WEB_NETWORK_CAPTURE_LIMITS } from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";

/**
 * Burp Suite "Save items" XML (Proxy history, Logger, Target site map): an
 * <items burpVersion exportTime> root with one <item> per message, holding
 * the raw HTTP request and response (base64 when base64="true"). Each item
 * becomes a HAR 1.2 entry so the pinned HAR decoder validates and projects
 * it; the raw messages are parsed here, never sent anywhere.
 */

type Header = { name: string; value: string };

const ZONES: Readonly<Record<string, number>> = {
  UTC: 0,
  GMT: 0,
  Z: 0,
  WET: 0,
  BST: 60,
  IST: 330,
  CET: 60,
  CEST: 120,
  EET: 120,
  EEST: 180,
  MSK: 180,
  JST: 540,
  KST: 540,
  AEST: 600,
  AEDT: 660,
  NZST: 720,
  NZDT: 780,
  EST: -300,
  EDT: -240,
  CST: -360,
  CDT: -300,
  MST: -420,
  MDT: -360,
  PST: -480,
  PDT: -420,
};
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** Java Date.toString ("Mon Oct 30 09:59:58 UTC 2023"), as Burp writes <time>. */
export const burpTime = (
  text: string,
): { iso: string; note: string | null } | null => {
  const match =
    /^\w{3} (\w{3}) (\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) (\d{4})$/u.exec(
      text.trim(),
    );
  if (match === null) return null;
  const [, month, day, hour, minute, second, zone = "UTC", year] = match;
  const monthIndex = MONTHS.indexOf(month ?? "");
  if (monthIndex < 0) return null;
  const known = ZONES[zone.toUpperCase()];
  const offset = /^[+-]\d\d:?\d\d$/u.test(zone)
    ? (zone.startsWith("-") ? -1 : 1) *
      (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(-2)))
    : known;
  const utc = Date.UTC(
    Number(year),
    monthIndex,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
  );
  return {
    iso: new Date(utc - (offset ?? 0) * 60_000).toISOString(),
    note:
      offset === undefined
        ? `Burp time zone ${zone} is unknown; read as UTC.`
        : null,
  };
};

const childText = (item: Element, name: string): string | null => {
  const node = item.getElementsByTagName(name)[0];
  return node === undefined ? null : (node.textContent ?? "");
};

const messageBytes = (item: Element, name: string): Buffer | null => {
  const node = item.getElementsByTagName(name)[0];
  const text = node?.textContent ?? "";
  if (node === undefined || text.length === 0) return null;
  return node.getAttribute("base64") === "true"
    ? Buffer.from(text, "base64")
    : Buffer.from(text, "latin1");
};

interface RawMessage {
  readonly start: string;
  readonly headers: Header[];
  readonly headerBytes: number;
  readonly body: Buffer;
}

/** Split a raw HTTP/1.x message into its start line, headers and body. */
const splitMessage = (bytes: Buffer): RawMessage => {
  const crlf = bytes.indexOf("\r\n\r\n");
  const lf = bytes.indexOf("\n\n");
  const end =
    crlf >= 0 && (lf < 0 || crlf < lf)
      ? crlf + 4
      : lf >= 0
        ? lf + 2
        : bytes.length;
  const lines = bytes
    .subarray(0, end)
    .toString("latin1")
    .split(/\r?\n/u)
    .filter((line) => line.length > 0);
  return {
    start: lines[0] ?? "",
    headers: lines.slice(1).flatMap((line) => {
      const colon = line.indexOf(":");
      return colon <= 0
        ? []
        : [
            {
              name: line.slice(0, colon).trim(),
              value: line.slice(colon + 1).trim(),
            },
          ];
    }),
    headerBytes: end,
    body: bytes.subarray(end),
  };
};

const header = (headers: readonly Header[], name: string): string | null =>
  headers.find((entry) => entry.name.toLowerCase() === name)?.value ?? null;

/** Undo chunked transfer coding; a malformed stream is kept as received. */
const dechunk = (body: Buffer): Buffer | null => {
  const parts: Buffer[] = [];
  let at = 0;
  for (;;) {
    const lineEnd = body.indexOf("\r\n", at);
    if (lineEnd < 0) return null;
    const size = Number.parseInt(
      body.subarray(at, lineEnd).toString("latin1").split(";")[0] ?? "",
      16,
    );
    if (!Number.isFinite(size) || size < 0) return null;
    if (size === 0) return Buffer.concat(parts);
    const start = lineEnd + 2;
    if (start + size > body.length) return null;
    parts.push(body.subarray(start, start + size));
    at = start + size + 2;
  }
};

const DECODERS: Readonly<
  Record<
    string,
    (input: Buffer, options: { maxOutputLength: number }) => Buffer
  >
> = {
  gzip: gunzipSync,
  "x-gzip": gunzipSync,
  deflate: inflateSync,
  br: brotliDecompressSync,
};

/** Response content as HAR content: decoded transfer and content codings, text or base64. */
const content = (
  message: RawMessage,
  notes: string[],
): Record<string, unknown> => {
  let body = message.body;
  if (
    header(message.headers, "transfer-encoding")
      ?.toLowerCase()
      .includes("chunked")
  ) {
    const dechunked = dechunk(body);
    if (dechunked === null)
      notes.push("Chunked response body is malformed; kept as received.");
    else body = dechunked;
  }
  const coding =
    header(message.headers, "content-encoding")?.toLowerCase() ?? null;
  const decode = coding === null ? undefined : DECODERS[coding];
  const compressed = body.length;
  if (decode !== undefined && body.length > 0)
    try {
      body = decode(body, {
        maxOutputLength: WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
      });
    } catch {
      notes.push(
        `Response body did not decode as ${coding ?? ""}; kept as received.`,
      );
    }
  const mimeType = header(message.headers, "content-type") ?? "";
  const text = new TextDecoder("utf-8", { fatal: true });
  let decoded: string | null = null;
  try {
    decoded = text.decode(body);
  } catch {
    decoded = null;
  }
  return {
    size: body.length,
    ...(body.length === compressed
      ? {}
      : { compression: body.length - compressed }),
    mimeType,
    ...(body.length === 0
      ? {}
      : decoded === null
        ? { text: body.toString("base64"), encoding: "base64" }
        : { text: decoded }),
  };
};

const cookies = (value: string | null): Header[] =>
  (value ?? "").split(";").flatMap((pair) => {
    const equals = pair.indexOf("=");
    return equals <= 0
      ? []
      : [
          {
            name: pair.slice(0, equals).trim(),
            value: pair.slice(equals + 1).trim(),
          },
        ];
  });

const request = (
  raw: Buffer,
  url: string,
  notes: string[],
): Record<string, unknown> => {
  const message = splitMessage(raw);
  const [method = "GET", , httpVersion = "HTTP/1.1"] = message.start.split(" ");
  let query: Header[] = [];
  try {
    query = [...new URL(url).searchParams].map(([name, value]) => ({
      name,
      value,
    }));
  } catch {
    notes.push("Request URL could not be parsed for its query string.");
  }
  let postData: Record<string, unknown> | undefined;
  if (message.body.length > 0)
    try {
      postData = {
        mimeType: header(message.headers, "content-type") ?? "",
        text: new TextDecoder("utf-8", { fatal: true }).decode(message.body),
      };
    } catch {
      notes.push(
        `Binary request body (${String(message.body.length)} bytes) is not representable as HAR postData text.`,
      );
    }
  return {
    method,
    url,
    httpVersion,
    cookies: cookies(header(message.headers, "cookie")),
    headers: message.headers,
    queryString: query,
    ...(postData === undefined ? {} : { postData }),
    headersSize: message.headerBytes,
    bodySize: message.body.length,
  };
};

const NO_RESPONSE = {
  status: 0,
  statusText: "",
  httpVersion: "",
  cookies: [],
  headers: [],
  content: { size: 0, mimeType: "" },
  redirectURL: "",
  headersSize: -1,
  bodySize: -1,
};

const response = (
  raw: Buffer | null,
  notes: string[],
): Record<string, unknown> => {
  if (raw === null) {
    notes.push("Burp recorded no response.");
    return NO_RESPONSE;
  }
  const message = splitMessage(raw);
  const match = /^(HTTP\/[\d.]+) (\d{3})(?: (.*))?$/u.exec(message.start);
  return {
    status: Number(match?.[2] ?? 0),
    statusText: match?.[3] ?? "",
    httpVersion: match?.[1] ?? "",
    cookies: message.headers
      .filter(({ name }) => name.toLowerCase() === "set-cookie")
      .flatMap(({ value }) => cookies(value.split(";")[0] ?? "")),
    headers: message.headers,
    content: content(message, notes),
    redirectURL: header(message.headers, "location") ?? "",
    headersSize: message.headerBytes,
    bodySize: message.body.length,
  };
};

const entry = (
  item: Element,
  fallbackTime: string,
): Record<string, unknown> => {
  const notes: string[] = [];
  const raw = messageBytes(item, "request");
  if (raw === null)
    throw new CaptureFormatError("format", "Burp item has no request.");
  const protocol = childText(item, "protocol") ?? "http";
  const host = childText(item, "host") ?? "";
  const port = childText(item, "port") ?? "";
  const url =
    childText(item, "url") ??
    `${protocol}://${host}${port === "" ? "" : `:${port}`}${childText(item, "path") ?? "/"}`;
  const time = burpTime(childText(item, "time") ?? "");
  if (time?.note) notes.push(time.note);
  if (time === null)
    notes.push(
      "Burp item time is missing or unreadable; the export time is used.",
    );
  const ip = item.getElementsByTagName("host")[0]?.getAttribute("ip") ?? "";
  const comment = childText(item, "comment") ?? "";
  const built = {
    startedDateTime: time?.iso ?? fallbackTime,
    time: 0,
    request: request(raw, url, notes),
    response: response(messageBytes(item, "response"), notes),
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
    ...(ip === "" ? {} : { serverIPAddress: ip }),
  };
  const remarks = [comment, ...notes].filter((text) => text.length > 0);
  return remarks.length === 0
    ? built
    : { ...built, comment: remarks.join(" ") };
};

/** Burp writes UTF-8 XML; anything else is refused before parsing. */
export const decodeBurpText = (bytes: Uint8Array): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CaptureFormatError(
      "format",
      "Burp export is not valid UTF-8 XML.",
    );
  }
};

/** Convert a Burp XML export into HAR 1.2 text for the HAR decoder. */
export const burpToHar = (xml: string): string => {
  if (/<!ENTITY/iu.test(xml))
    throw new CaptureFormatError(
      "format",
      "Burp exports declare no entities; refusing an XML entity declaration.",
    );
  let root: Element | null;
  try {
    root = new DOMParser({ onError: onWarningStopParsing }).parseFromString(
      xml,
      "text/xml",
    ).documentElement;
  } catch (cause: unknown) {
    throw new CaptureFormatError(
      "format",
      `Burp export is not well-formed XML: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  if (root?.tagName !== "items")
    throw new CaptureFormatError(
      "format",
      "Not a Burp Suite XML export (expected an <items> root).",
    );
  const exported =
    burpTime(root.getAttribute("exportTime") ?? "")?.iso ??
    new Date(0).toISOString();
  const items = Array.from(root.getElementsByTagName("item"));
  return JSON.stringify({
    log: {
      version: "1.2",
      creator: {
        name: "Burp Suite",
        version: root.getAttribute("burpVersion") ?? "unknown",
      },
      entries: items.map((item) => entry(item, exported)),
    },
  });
};
