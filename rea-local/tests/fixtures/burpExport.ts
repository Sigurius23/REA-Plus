import { gzipSync } from "node:zlib";

/**
 * Burp Suite "Save items" XML as Burp writes it: a DOCTYPE with element
 * declarations, CDATA sections, raw HTTP messages in base64, and Java
 * Date.toString times.
 */

const message = (
  lines: readonly string[],
  body: Buffer = Buffer.alloc(0),
): string =>
  Buffer.concat([
    Buffer.from(`${lines.join("\r\n")}\r\n\r\n`, "latin1"),
    body,
  ]).toString("base64");

export const BURP_JSON_BODY = '{"player":"Ada","score":4200}';
export const BURP_HTML_BODY = "<html><body>Leaderboard</body></html>";

const chunked = (text: string): Buffer => {
  const bytes = Buffer.from(text, "utf8");
  const half = Math.floor(bytes.length / 2);
  return Buffer.concat([
    Buffer.from(`${half.toString(16)}\r\n`),
    bytes.subarray(0, half),
    Buffer.from("\r\n"),
    Buffer.from(`${(bytes.length - half).toString(16)}\r\n`),
    bytes.subarray(half),
    Buffer.from("\r\n0\r\n\r\n"),
  ]);
};

const item = (
  fields: Record<string, string>,
  request: string,
  response: string | null,
) => `  <item>
    <time>${fields["time"] ?? "Fri Oct 16 09:59:58 UTC 2026"}</time>
    <url><![CDATA[${fields["url"] ?? ""}]]></url>
    <host ip="${fields["ip"] ?? "203.0.113.7"}">${fields["host"] ?? "api.example.test"}</host>
    <port>${fields["port"] ?? "443"}</port>
    <protocol>${fields["protocol"] ?? "https"}</protocol>
    <method><![CDATA[${fields["method"] ?? "GET"}]]></method>
    <path><![CDATA[${fields["path"] ?? "/"}]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[${request}]]></request>
    <status>${fields["status"] ?? ""}</status>
    <responselength>0</responselength>
    <mimetype>${fields["mimetype"] ?? ""}</mimetype>
    <response base64="true"><![CDATA[${response ?? ""}]]></response>
    <comment>${fields["comment"] ?? ""}</comment>
  </item>`;

export const createBurpExport = (): string => `<?xml version="1.1"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
]>
<items burpVersion="2026.9.2" exportTime="Fri Oct 16 10:00:00 UTC 2026">
${item(
  {
    url: "https://api.example.test/scores?season=3&mode=ranked",
    method: "POST",
    path: "/scores?season=3&mode=ranked",
    status: "200",
    mimetype: "JSON",
    comment: "score submit",
  },
  message(
    [
      "POST /scores?season=3&mode=ranked HTTP/1.1",
      "Host: api.example.test",
      "Authorization: Bearer secret-token",
      "Cookie: session=abc123; theme=dark",
      "Content-Type: application/json",
    ],
    Buffer.from(BURP_JSON_BODY),
  ),
  message(
    [
      "HTTP/1.1 200 OK",
      "Content-Type: application/json",
      "Content-Encoding: gzip",
      "Set-Cookie: session=def456; Path=/; HttpOnly",
    ],
    gzipSync(Buffer.from('{"rank":12}')),
  ),
)}
${item(
  {
    url: "http://www.example.test/leaderboard",
    protocol: "http",
    port: "80",
    host: "www.example.test",
    time: "Fri Oct 16 11:59:58 CEST 2026",
    status: "200",
  },
  message(["GET /leaderboard HTTP/1.1", "Host: www.example.test"]),
  message(
    [
      "HTTP/1.1 200 OK",
      "Content-Type: text/html",
      "Transfer-Encoding: chunked",
    ],
    chunked(BURP_HTML_BODY),
  ),
)}
${item(
  {
    url: "https://cdn.example.test/logo.png",
    path: "/logo.png",
    host: "cdn.example.test",
    time: "Fri Oct 16 09:59:59 XYZ 2026",
  },
  message(["GET /logo.png HTTP/2", "Host: cdn.example.test"]),
  message(
    ["HTTP/2 200", "Content-Type: image/png"],
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe]),
  ),
)}
${item({ url: "https://api.example.test/ping", path: "/ping" }, message(["GET /ping HTTP/1.1", "Host: api.example.test"]), null)}
</items>
`;
