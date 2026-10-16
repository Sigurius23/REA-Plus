import { execFile } from "node:child_process";
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createProtocolFieldsService } from "../../../../src/composition/protocol.js";
import type { ProtocolFieldsReport } from "../../../../src/domain/protocol/protocolFields.js";
import { SCAPY_CAPTURES } from "../../../support/protocol/scapyCaptures.js";
import { tsharkFieldStarts } from "../../../support/protocol/tsharkFields.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/**
 * Real-tool lanes. REA_VERIFY_PROTOCOL_SAMPLES is a folder of Wireshark's
 * sample captures (wiki.wireshark.org/SampleCaptures) under their published
 * names; REA_VERIFY_TSHARK is tshark, whose dissectors say where fields
 * really start; REA_VERIFY_SCAPY_PYTHON is a Python with scapy, which
 * writes captures of protocols with known layouts.
 */
const SAMPLES = process.env["REA_VERIFY_PROTOCOL_SAMPLES"];
const TSHARK = process.env["REA_VERIFY_TSHARK"];
const PYTHON = process.env["REA_VERIFY_SCAPY_PYTHON"];

const SEMANTIC = new Set([
  "type",
  "length",
  "counter",
  "checksum",
  "timestamp",
]);
const service = createProtocolFieldsService();
let root = "";
beforeAll(async () => {
  root = (await createTestWorkspace("rea-protocol-real-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const infer = async (input: Record<string, unknown>) => {
  const result = await service.inspect({ limit: 1000, ...input });
  if (!result.ok) throw result.error;
  return result.value.normalized_result as ProtocolFieldsReport;
};

const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

/** Share of messages in which each semantic field starts where tshark starts a field. */
const semanticPrecision = async (
  capture: string,
  filter: string,
  input: Record<string, unknown>,
) => {
  const truth = await tsharkFieldStarts(TSHARK ?? "", capture, filter);
  const { messages } = await infer({
    ...input,
    path: capture,
    view: "messages",
  });
  const { fields } = await infer({ ...input, path: capture, view: "fields" });
  let hits = 0;
  let total = 0;
  for (const field of fields.filter(
    ({ kind, from }) => SEMANTIC.has(kind) && from === "start",
  ))
    for (const message of messages.filter(
      ({ format }) => format === field.format,
    )) {
      total += 1;
      if (
        field.offset === 0 ||
        truth[message.index]?.has(field.offset) === true
      )
        hits += 1;
    }
  return { hits, total, messages: messages.length, packets: truth.length };
};

const has = (
  report: ProtocolFieldsReport,
  match: Partial<ProtocolFieldsReport["fields"][number]>,
) =>
  report.fields.some((field) =>
    Object.entries(match).every(
      ([key, value]) => field[key as keyof typeof field] === value,
    ),
  );

describe.skipIf(SAMPLES === undefined)("Wireshark's sample captures", () => {
  const sample = (name: string) => join(SAMPLES ?? "", name);

  it("frames IEC 104 and S7comm (TPKT) streams by their length fields", async () => {
    if (await exists(sample("iec104.pcap")))
      expect(
        (await infer({ path: sample("iec104.pcap") })).framing,
      ).toMatchObject({
        kind: "length_prefix",
        offset: 1,
        width: 1,
        adjust: 2,
      });
    if (await exists(sample("s7comm_reading_plc_status.pcap"))) {
      const report = await infer({
        path: sample("s7comm_reading_plc_status.pcap"),
        view: "fields",
      });
      expect(report.framing).toMatchObject({
        kind: "length_prefix",
        offset: 2,
        width: 2,
        endian: "big",
        adjust: 0,
      });
      expect(has(report, { offset: 0, length: 2, kind: "constant" })).toBe(
        true,
      );
    }
  });

  it("finds TFTP block numbers, NTP timestamps and the DHCP magic cookie", async () => {
    if (await exists(sample("tftp_rrq.pcap")))
      expect(
        has(await infer({ path: sample("tftp_rrq.pcap"), view: "fields" }), {
          offset: 2,
          length: 2,
          kind: "counter",
          encoding: "u16be",
        }),
      ).toBe(true);
    if (await exists(sample("NTP_sync.pcap"))) {
      const ntp = await infer({
        path: sample("NTP_sync.pcap"),
        port: 123,
        view: "fields",
      });
      // The transmit timestamp's seconds, in every format.
      expect(
        new Set(
          ntp.fields
            .filter(({ offset, kind }) => offset === 40 && kind === "timestamp")
            .map(({ format }) => format),
        ).size,
      ).toBe(ntp.summary.formats);
    }
    if (await exists(sample("dhcp.pcap"))) {
      const dhcp = await infer({ path: sample("dhcp.pcap"), view: "fields" });
      expect(
        dhcp.fields.some(
          ({ kind, offset, length }) =>
            kind === "constant" &&
            offset <= 236 &&
            offset + (length ?? 0) >= 240,
        ),
      ).toBe(true);
    }
  });

  it.skipIf(TSHARK === undefined)(
    "puts semantic fields where tshark's dissectors put field starts",
    async () => {
      // CoAP's token is a 32-bit value counting in its low half; that half is
      // read as a 16-bit counter two bytes into the field, which tshark does
      // not split, so half its semantic fields miss.
      const cases = [
        ["tftp_rrq.pcap", "udp", {}, 1],
        ["NTP_sync.pcap", "udp.port==123", { port: 123 }, 1],
        ["dns.cap", "udp", { transport: "udp" }, 1],
        ["coap-cbor.pcap", "udp", {}, 0.5],
      ] as const;
      let checked = 0;
      for (const [name, filter, input, expected] of cases) {
        if (!(await exists(sample(name)))) continue;
        const result = await semanticPrecision(sample(name), filter, input);
        expect(result.messages, name).toBe(result.packets);
        expect(result.total, name).toBeGreaterThan(0);
        expect(
          result.hits / result.total,
          `${name}: ${String(result.hits)}/${String(result.total)}`,
        ).toBeGreaterThanOrEqual(expected);
        checked += 1;
      }
      expect(checked).toBeGreaterThan(0);
    },
    300_000,
  );
});

describe.skipIf(PYTHON === undefined)("captures scapy writes", () => {
  it("recovers the layouts of protocols it generated", async () => {
    await writeFile(join(root, "captures.py"), SCAPY_CAPTURES);
    await promisify(execFile)(
      PYTHON ?? "",
      ["-I", join(root, "captures.py"), root],
      { cwd: root, timeout: 300_000 },
    );
    const modbus = await infer({
      path: join(root, "modbus.pcap"),
      view: "fields",
    });
    expect(modbus.framing).toMatchObject({
      kind: "length_prefix",
      offset: 4,
      width: 2,
      endian: "big",
      adjust: 6,
    });
    for (const match of [
      { offset: 0, length: 2, kind: "counter", encoding: "u16be" },
      { offset: 2, length: 2, kind: "constant" },
      { offset: 4, length: 2, kind: "length" },
      { offset: 7, length: 1, kind: "type" },
    ] as const)
      expect(has(modbus, match), JSON.stringify(match)).toBe(true);
    const tftp = await infer({ path: join(root, "tftp.pcap"), view: "fields" });
    expect([
      has(tftp, { offset: 0, length: 2, kind: "type" }),
      has(tftp, { offset: 2, length: 2, kind: "counter" }),
    ]).toEqual([true, true]);
    const game = await infer({ path: join(root, "game.pcap"), view: "fields" });
    for (const match of [
      { offset: 5, length: 4, kind: "counter", encoding: "u32le" },
      { offset: 9, length: 2, kind: "length", encoding: "u16le" },
      {
        offset: 11,
        length: 4,
        kind: "checksum",
        detail: "crc32 of bytes 19 to the end",
      },
      { offset: 15, length: 4, kind: "timestamp" },
    ] as const)
      expect(has(game, match), JSON.stringify(match)).toBe(true);
    expect(
      (await infer({ path: join(root, "lenprefix.pcap") })).framing,
    ).toMatchObject({
      kind: "length_prefix",
      offset: 0,
      width: 4,
      endian: "little",
      adjust: 0,
    });
    expect(
      (await infer({ path: join(root, "lines.pcap") })).framing,
    ).toMatchObject({ kind: "delimiter", delimiter: "\r\n" });
    if (TSHARK !== undefined)
      for (const name of ["dns.pcap", "tftp.pcap"]) {
        const result = await semanticPrecision(join(root, name), "udp", {});
        expect(result.hits, name).toBe(result.total);
      }
  }, 600_000);
});
