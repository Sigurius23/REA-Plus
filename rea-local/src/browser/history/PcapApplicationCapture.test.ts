import { describe, expect, it } from "vitest";

import {
  DNS_QUERY,
  DNS_RESPONSE,
  HTTP_REQUEST,
  HTTP_RESPONSE,
  TLS_CLIENT_HELLO,
  TLS_SERVER_HELLO,
} from "./PcapApplication.fixture.js";
import { decodePcapCapture } from "./PcapCapture.js";
import { classicPcap, ethernetIpv4Frame } from "./PcapCapture.fixture.js";

const decodeOne = (frame: Buffer, sensitive: readonly string[] = []) => {
  const [record] = decodePcapCapture(
    classicPcap([frame]),
    "pcap",
    sensitive,
  ).records;
  if (record === undefined) throw new Error("expected one record");
  return record;
};
const reportedApplication = (record: ReturnType<typeof decodeOne>) =>
  (record.reported as { application: unknown }).application;
const http = (payload: Buffer, toServer = true) =>
  ethernetIpv4Frame(
    "tcp",
    payload,
    toServer
      ? { source: 55_010, destination: 8080 }
      : { source: 8080, destination: 55_010 },
  );

describe("PCAP DNS and TLS metadata", () => {
  it("decodes a recorded DNS query and CNAME/A response", () => {
    const query = decodeOne(ethernetIpv4Frame("udp", DNS_QUERY));
    expect(reportedApplication(query)).toMatchObject({
      protocol: "dns",
      transport: "udp",
      header: { id: 0xc69d, response: false, recursion_desired: true },
      counts: { questions: 1, answers: 0, additionals: 1 },
      questions: [{ name: "api.example.test", type: 1, type_name: "A" }],
      additionals: [{ name: ".", type: 41, type_name: "OPT" }],
      decode_status: "decoded",
    });
    const response = decodeOne(
      ethernetIpv4Frame("udp", DNS_RESPONSE, {
        source: 53,
        destination: 53_000,
      }),
    );
    expect(reportedApplication(response)).toMatchObject({
      header: { response: true, response_code_name: "NOERROR" },
      answers: [
        {
          name: "api.example.test",
          type_name: "CNAME",
          ttl: 300,
          target: "cdn.example.test",
        },
        {
          name: "cdn.example.test",
          type_name: "A",
          ttl: 60,
          address: "192.0.2.10",
        },
      ],
      decode_status: "decoded",
    });
    // DNS metadata is evidence about the packet, not a credential.
    expect(response.binary_fields[0]?.state).toBe("retained");
  });

  it("reports malformed and truncated DNS without guessing records", () => {
    const loop = Buffer.concat([
      DNS_QUERY.subarray(0, 12),
      Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]),
    ]);
    expect(
      reportedApplication(decodeOne(ethernetIpv4Frame("udp", loop))),
    ).toMatchObject({ questions: [], decode_status: "name-pointer-loop" });
    expect(
      reportedApplication(
        decodeOne(ethernetIpv4Frame("udp", DNS_RESPONSE.subarray(0, 40))),
      ),
    ).toMatchObject({ answers: [], decode_status: "truncated-record" });
  });

  it("extracts SNI, ALPN and versions from recorded TLS 1.3 hellos", () => {
    expect(
      reportedApplication(
        decodeOne(ethernetIpv4Frame("tcp", TLS_CLIENT_HELLO)),
      ),
    ).toMatchObject({
      protocol: "tls",
      handshake: "client_hello",
      legacy_version: "TLS 1.2",
      cipher_suite_count: 31,
      server_names: [{ name_type: 0, name: "api.example.test" }],
      alpn: ["h2", "http/1.1"],
      supported_versions: ["TLS 1.3", "TLS 1.2"],
      complete: true,
    });
    expect(
      reportedApplication(
        decodeOne(ethernetIpv4Frame("tcp", TLS_SERVER_HELLO)),
      ),
    ).toMatchObject({
      handshake: "server_hello",
      cipher_suite: "0x1302",
      supported_versions: ["TLS 1.3"],
      complete: true,
    });
    expect(
      reportedApplication(
        decodeOne(ethernetIpv4Frame("tcp", TLS_CLIENT_HELLO.subarray(0, 120))),
      ),
    ).toMatchObject({
      handshake: "client_hello",
      complete: false,
      decode_status: "hello-spans-segments",
    });
  });

  it("leaves unrecognized payloads undecoded", () => {
    expect(
      reportedApplication(
        decodeOne(ethernetIpv4Frame("tcp", Buffer.from("payload"))),
      ),
    ).toBeNull();
    expect(
      reportedApplication(
        decodeOne(
          ethernetIpv4Frame("udp", Buffer.from("payload"), {
            source: 40_000,
            destination: 9_999,
          }),
        ),
      ),
    ).toBeNull();
  });
});

describe("PCAP HTTP/1.x metadata", () => {
  it("decodes recorded HTTP heads and withholds credentials and their frames", () => {
    const request = decodeOne(http(HTTP_REQUEST));
    expect(reportedApplication(request)).toEqual({
      protocol: "http/1.1",
      kind: "request",
      method: "GET",
      target: "/api/login?next=%2Fhome",
      headers: [
        { name: "Host", value: "127.0.0.1:8080" },
        { name: "Authorization", value: null },
        { name: "User-Agent", value: "curl/8.5.0" },
        { name: "Accept", value: "*/*" },
        { name: "Cookie", value: null },
      ],
      head_complete: true,
      body_bytes_in_segment: 0,
    });
    expect(request.redactions).toEqual([
      {
        pointer: "/application/headers/1/value",
        reason: "transport-credential",
      },
      {
        pointer: "/application/headers/4/value",
        reason: "transport-credential",
      },
      { pointer: "/frame/data", reason: "transport-credential" },
    ]);
    expect(request.binary_fields[0]).toMatchObject({
      state: "redacted",
      content_base64: null,
      sha256: null,
    });
    expect(JSON.stringify(request)).not.toContain("YWxpY2U6czNjcmV0LXBhc3M");

    const response = decodeOne(http(HTTP_RESPONSE, false));
    expect(reportedApplication(response)).toMatchObject({
      protocol: "http/1.1",
      kind: "response",
      status: 302,
      reason: "Found",
      headers: expect.arrayContaining([
        { name: "Location", value: "http://127.0.0.1:8080/next" },
        { name: "Set-Cookie", value: null },
      ]),
    });
    expect(JSON.stringify(response)).not.toMatch(
      /hunter2|server-issued-secret/u,
    );
  });

  it("keeps a head cut at the segment end and redacts a cut credential line", () => {
    const cut = HTTP_REQUEST.subarray(0, HTTP_REQUEST.indexOf("Basic") + 8);
    const record = decodeOne(http(cut));
    expect(reportedApplication(record)).toMatchObject({
      kind: "request",
      headers: [{ name: "Host", value: "127.0.0.1:8080" }],
      partial_line: null,
      head_complete: false,
    });
    expect(record.redactions).toContainEqual({
      pointer: "/application/partial_line",
      reason: "transport-credential",
    });
    expect(record.binary_fields[0]?.state).toBe("redacted");
  });

  it("strips userinfo from an absolute-form request target", () => {
    const proxied = Buffer.from(
      "GET http://user:pw@example.test/a HTTP/1.1\r\nHost: example.test\r\n\r\n",
      "latin1",
    );
    const record = decodeOne(http(proxied));
    expect(reportedApplication(record)).toMatchObject({
      target: "http://example.test/a",
    });
    expect(record.redactions).toContainEqual({
      pointer: "/application/target",
      reason: "transport-credential",
    });
  });
});
