import { describe, expect, it } from "vitest";

import {
  byteStream,
  decoderStack,
  parseAnnotations,
  parseDecoderClasses,
  SIGROK_LIMITS,
  SigrokDecodeRejected,
} from "./SigrokCli.js";
import { parseSamplerate } from "./SigrokSession.js";

describe("sigrok text formats", () => {
  it("reads every samplerate unit sigrok writes", () => {
    expect(
      ["200 kHz", "1 MHz", "1.5 GHz", "100 Hz", "48000"].map(parseSamplerate),
    ).toEqual([200e3, 1e6, 1.5e9, 100, 48000]);
    expect(() => parseSamplerate("fast")).toThrow(/Unsupported samplerate/u);
  });

  it("builds stacked -P arguments", () => {
    expect(
      decoderStack([
        {
          id: "spi",
          channels: { clk: "D0", mosi: "D1" },
          options: { cpol: 0 },
        },
        { id: "spiflash", channels: {}, options: { format: "hex" } },
      ]),
    ).toBe("spi:clk=D0:mosi=D1:cpol=0,spiflash:format=hex");
  });

  it("parses annotation classes and sample-numbered lines", () => {
    expect(
      parseDecoderClasses(
        "ID: uart\nAnnotation classes:\n- rx-data: RX data\n- tx-data: TX data\nAnnotation rows:\n- x",
      ),
    ).toEqual([
      { id: "rx-data", description: "RX data" },
      { id: "tx-data", description: "TX data" },
    ]);
    expect(
      parseAnnotations("10-30 i2c-1: Address read: 50\n", "address-read", 1e6),
    ).toEqual([
      {
        class: "address-read",
        decoder: "i2c-1",
        start_sample: 10,
        end_sample: 30,
        start_s: 0.00001,
        end_s: 0.00003,
        text: "Address read: 50",
      },
    ]);
    expect(() => parseAnnotations("garbage\n", null, 1)).toThrow(
      SigrokDecodeRejected,
    );
  });

  it("joins only all-hex-byte classes and bounds the inline stream", () => {
    const annotation = (text: string) => ({
      class: "rx-data",
      decoder: "uart-1",
      start_sample: 0,
      end_sample: 1,
      start_s: 0,
      end_s: 0,
      text,
    });
    expect(
      byteStream("rx-data", [annotation("48"), annotation("Start bit")]),
    ).toBeNull();
    const many = Array.from({ length: SIGROK_LIMITS.byteStreamBytes + 3 }, () =>
      annotation("41"),
    );
    expect(byteStream("rx-data", many)).toMatchObject({
      bytes: SIGROK_LIMITS.byteStreamBytes + 3,
      truncated: true,
    });
  });
});
