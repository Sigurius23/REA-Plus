import { describe, expect, it } from "vitest";

import {
  BURP_HTML_BODY,
  BURP_JSON_BODY,
  createBurpExport,
} from "../../../tests/fixtures/burpExport.js";
import { burpTime, burpToHar, decodeBurpText } from "./BurpExport.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { decodeHarCapture } from "./HarCapture.js";

type Entry = Record<string, any>;

const entries = (): Entry[] =>
  JSON.parse(burpToHar(createBurpExport())).log.entries;

describe("Burp Suite XML exports", () => {
  it("converts items into HAR 1.2 entries the HAR decoder accepts", () => {
    const har = JSON.parse(burpToHar(createBurpExport()));
    expect(har.log.creator).toEqual({
      name: "Burp Suite",
      version: "2026.9.2",
    });
    const decoded = decodeHarCapture(JSON.stringify(har), []);
    expect(decoded.total_records).toBe(4);
    expect(decoded.records.map(({ ordinal }) => ordinal)).toEqual([0, 1, 2, 3]);
  });

  it("parses raw requests: method, URL, query, cookies and body", () => {
    const [post] = entries();
    expect(post?.request).toMatchObject({
      method: "POST",
      url: "https://api.example.test/scores?season=3&mode=ranked",
      httpVersion: "HTTP/1.1",
      queryString: [
        { name: "season", value: "3" },
        { name: "mode", value: "ranked" },
      ],
      cookies: [
        { name: "session", value: "abc123" },
        { name: "theme", value: "dark" },
      ],
      postData: { mimeType: "application/json", text: BURP_JSON_BODY },
      bodySize: BURP_JSON_BODY.length,
    });
    expect(post).toMatchObject({
      serverIPAddress: "203.0.113.7",
      comment: "score submit",
      startedDateTime: "2026-10-16T09:59:58.000Z",
    });
  });

  it("decodes gzip, chunked and binary responses", () => {
    const [post, page, image, ping] = entries();
    expect(post?.response).toMatchObject({
      status: 200,
      statusText: "OK",
      cookies: [{ name: "session", value: "def456" }],
      content: { mimeType: "application/json", text: '{"rank":12}', size: 11 },
    });
    expect(page?.response.content).toMatchObject({
      mimeType: "text/html",
      text: BURP_HTML_BODY,
    });
    expect(page?.startedDateTime).toBe("2026-10-16T09:59:58.000Z");
    expect(image?.response).toMatchObject({
      httpVersion: "HTTP/2",
      status: 200,
      statusText: "",
    });
    expect(image?.response.content).toEqual({
      size: 6,
      mimeType: "image/png",
      text: "iVBOR//+",
      encoding: "base64",
    });
    expect(image?.comment).toBe("Burp time zone XYZ is unknown; read as UTC.");
    expect(ping?.response).toMatchObject({ status: 0, headersSize: -1 });
    expect(ping?.comment).toBe("Burp recorded no response.");
  });

  it("redacts transport credentials through the HAR decoder", () => {
    const decoded = decodeHarCapture(burpToHar(createBurpExport()), [
      "secret-token",
    ]);
    expect(JSON.stringify(decoded.records[0]?.reported)).not.toContain(
      "secret-token",
    );
    expect(decoded.records[0]?.redactions.length).toBeGreaterThan(0);
  });

  it("reads Java Date.toString times and refuses other documents", () => {
    expect(burpTime("Mon Oct 30 09:59:58 EST 2023")?.iso).toBe(
      "2023-10-30T14:59:58.000Z",
    );
    expect(burpTime("yesterday")).toBeNull();
    for (const xml of [
      "<log><entry/></log>",
      "<items><item><time>x",
      '<?xml version="1.0"?><!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]><items>&x;</items>',
    ])
      expect(() => burpToHar(xml)).toThrow(CaptureFormatError);
    expect(() => decodeBurpText(Buffer.from([0xff, 0xfe, 0x00]))).toThrow(
      "not valid UTF-8",
    );
  });
});
