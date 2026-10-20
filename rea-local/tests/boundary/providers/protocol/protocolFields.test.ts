import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createProtocolFieldsService } from "../../../../src/composition/protocol.js";
import type { ProtocolFieldsReport } from "../../../../src/domain/protocol/protocolFields.js";
import {
  gamePackets,
  lengthPrefixedStream,
  pcap,
  pcapng,
} from "../../../fixtures/protocolFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createProtocolFieldsService();
let root = "";
const path = (name: string) => join(root, name);

beforeAll(async () => {
  root = (await createTestWorkspace("rea-protocol-")).root;
  const game = gamePackets();
  const stream = lengthPrefixedStream();
  const lines = [
    "PING 1",
    "SAY hello world",
    "MOVE 4 7",
    "PING 2",
    "MOVE 9 12",
    "SAY gg all",
    "PING 3",
    "MOVE 1 1",
  ].map((line, index) => ({
    time: 1_760_000_000 + index,
    src: [10, 0, 4, 2] as const,
    dst: [10, 0, 4, 3] as const,
    sport: 46000,
    dport: 6667,
    seq: 1 + index * 100,
    payload: Buffer.from(`${line}\r\n`),
  }));
  let at = 1;
  const contiguous = lines.map((packet) => {
    const seq = at;
    at += packet.payload.length;
    return { ...packet, seq };
  });
  const files: Record<string, Buffer> = {
    "game.pcap": pcap(game),
    "game.pcapng": pcapng(game),
    "stream.pcap": pcap(stream.packets),
    "lines.pcap": pcap(contiguous),
    "mixed.pcap": pcap([...game.slice(0, 20), ...stream.packets]),
    "hex.txt": Buffer.from(
      `# copied from a debugger\n${game
        .slice(0, 60)
        .map(({ payload }) => payload.toString("hex").replace(/(..)/gu, "$1 "))
        .join("\n")}\n`,
    ),
    "junk.bin": Buffer.from("not a capture at all \x00\x01", "latin1"),
  };
  for (const [name, bytes] of Object.entries(files))
    await writeFile(path(name), bytes);
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const infer = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as ProtocolFieldsReport;
};
const layout = (report: ProtocolFieldsReport, format: number) =>
  report.fields
    .filter((field) => field.format === format)
    .map(({ offset, length, kind, encoding, detail }) => [
      offset,
      length,
      kind,
      encoding,
      detail,
    ]);

const HEADER = [
  [0, 4, "constant", null, null],
  [4, 1, "type", null, "tells this format from the others"],
  [5, 4, "counter", "u32le", "increments by 1"],
  [9, 2, "length", "u16le", "message length - 19"],
  [11, 4, "checksum", "u32le", "crc32 of bytes 19 to the end"],
  [15, 4, "timestamp", "u32le", "seconds since 1970"],
];

describe("binary datagrams", () => {
  it("recovers a game protocol's formats and header fields from UDP", async () => {
    for (const name of ["game.pcap", "game.pcapng"]) {
      const report = await infer({ path: path(name) });
      expect(report.source, name).toMatchObject({
        format: name.endsWith("ng") ? "pcapng" : "pcap",
        frames: 240,
        analysed: 240,
      });
      expect(report.framing.kind).toBe("datagrams");
      expect(report.inference.byte_order).toBe("little");
      expect(
        report.formats
          .map(({ key, key_offset, key_width }) => [key, key_offset, key_width])
          .sort(),
      ).toEqual([
        ["01", 4, 1],
        ["02", 4, 1],
        ["03", 4, 1],
      ]);
    }
    const formats = await infer({ path: path("game.pcap") });
    const id = (key: string) =>
      formats.formats.find((format) => format.key === key)?.id ?? -1;
    const fields = await infer({
      path: path("game.pcap"),
      view: "fields",
      limit: 1000,
    });
    expect(layout(fields, id("01"))).toEqual([
      ...HEADER,
      [19, 4, "float", "f32le", null],
      [23, 4, "float", "f32le", null],
      [27, 4, "float", "f32le", null],
      [31, 1, "enum", null, null],
    ]);
    expect(layout(fields, id("02"))).toEqual([
      ...HEADER,
      [19, null, "variable", "ascii", expect.stringContaining("bytes")],
    ]);
    expect(layout(fields, id("03"))).toEqual([
      ...HEADER,
      [19, 8, "id", null, null],
    ]);
    expect(
      fields.fields.find(({ kind }) => kind === "constant")?.samples,
    ).toEqual(['"GAME"']);
  });

  it("lists messages and flows, and filters by format and query", async () => {
    const messages = await infer({
      path: path("game.pcap"),
      view: "messages",
      format: 0,
      limit: 3,
    });
    expect(messages.messages.every(({ format }) => format === 0)).toBe(true);
    expect(messages.messages[0]).toMatchObject({
      flow: "udp|10.0.0.1:40001|10.0.0.9:7777",
      direction: "a-to-b",
    });
    expect(messages.messages[0]?.hex.startsWith("47414d45")).toBe(true);
    const flows = await infer({ path: path("game.pcap"), view: "flows" });
    expect(
      flows.flows.map(({ flow, messages: count }) => [flow, count]),
    ).toEqual([
      ["udp|10.0.0.1:40001|10.0.0.9:7777", 120],
      ["udp|10.0.0.2:40002|10.0.0.9:7777", 120],
    ]);
    const checksums = await infer({
      path: path("game.pcap"),
      view: "fields",
      query: "crc32",
    });
    expect(checksums.fields).toHaveLength(3);
    const port = await infer({ path: path("game.pcap"), port: 40002 });
    expect(port.summary.messages).toBe(120);
  });

  it("reads hex lines, without the timing or flows a capture gives", async () => {
    const report = await infer({
      path: path("hex.txt"),
      view: "fields",
      limit: 1000,
    });
    expect(report.source.format).toBe("hex_lines");
    expect(report.framing.kind).toBe("lines");
    const kinds = new Set<string>(report.fields.map(({ kind }) => kind));
    expect(
      ["type", "length", "checksum"].every((kind) => kinds.has(kind)),
    ).toBe(true);
    // Two clients' sequence numbers interleave without flows, and there are no packet times.
    expect([kinds.has("counter"), kinds.has("timestamp")]).toEqual([
      false,
      false,
    ]);
  });
});

describe("TCP streams", () => {
  it("reassembles out-of-order and repeated segments and finds the length prefix", async () => {
    const report = await infer({ path: path("stream.pcap") });
    expect(report.framing).toEqual({
      kind: "length_prefix",
      offset: 0,
      width: 4,
      endian: "little",
      adjust: 0,
      delimiter: null,
    });
    expect(report.summary.messages).toBe(
      lengthPrefixedStream().messages.length,
    );
    const messages = await infer({
      path: path("stream.pcap"),
      view: "messages",
      limit: 1000,
    });
    expect(messages.messages.map(({ hex }) => hex)).toEqual(
      lengthPrefixedStream().messages.map((message) =>
        message.subarray(0, 64).toString("hex"),
      ),
    );
    const fields = await infer({ path: path("stream.pcap"), view: "fields" });
    expect(fields.fields[0]).toMatchObject({
      offset: 0,
      length: 4,
      kind: "length",
      encoding: "u32le",
      detail: "message length; frames the TCP stream",
    });
  });

  it("splits text streams into lines and groups them by first word", async () => {
    const report = await infer({ path: path("lines.pcap") });
    expect(report.framing).toMatchObject({
      kind: "delimiter",
      delimiter: "\r\n",
    });
    expect(report.inference.text).toBe(true);
    expect(
      report.formats.map(({ key, messages: count }) => [key, count]),
    ).toEqual([
      ["PING", 3],
      ["SAY", 2],
      ["MOVE", 3],
    ]);
  });
});

describe("refusals", () => {
  it("refuses files, selections and formats that do not fit", async () => {
    for (const [input, field] of [
      [{ path: path("junk.bin") }, "path"],
      [{ path: path("mixed.pcap") }, "transport"],
      [{ path: path("game.pcap"), port: 1 }, "path"],
      [{ path: path("game.pcap"), view: "fields", format: 9 }, "format"],
    ] as const)
      expect(await service.inspect(input), JSON.stringify(input)).toMatchObject(
        { ok: false, error: { issues: [{ path: [field] }] } },
      );
    const udp = await infer({ path: path("mixed.pcap"), transport: "udp" });
    expect(udp.summary.messages).toBe(20);
  });
});
