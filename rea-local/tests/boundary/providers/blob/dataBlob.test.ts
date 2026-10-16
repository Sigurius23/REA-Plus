import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  brotliCompressSync,
  deflateRawSync,
  deflateSync,
  gzipSync,
  zstdCompressSync,
} from "node:zlib";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createDataBlobService } from "../../../../src/composition/blob.js";
import type { DataBlobReport } from "../../../../src/domain/blob/dataBlob.js";
import {
  bedrockLevel,
  bsonSave,
  cbor,
  lz4Stored,
  msgpack,
  nbtSave,
  protobufSave,
  regionFile,
  SAVE,
} from "../../../fixtures/blobFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createDataBlobService();
let root = "";
const files: Record<string, Buffer> = {};
const path = (name: string) => join(root, name);

beforeAll(async () => {
  root = (await createTestWorkspace("rea-blob-")).root;
  Object.assign(files, {
    "save.pb": protobufSave(),
    "save.msgpack": msgpack(SAVE),
    "save.cbor": cbor(SAVE),
    "save.bson": bsonSave(),
    "level.dat": gzipSync(nbtSave()),
    "bedrock.dat": bedrockLevel(),
    "save.json": Buffer.from(
      '{"player":"Ana","hp":[1,2,3],"inventory":{"sword":1}}',
    ),
    "save.b64": Buffer.from(gzipSync(msgpack(SAVE)).toString("base64")),
    "save.hex": Buffer.from(protobufSave().toString("hex")),
    "save.zlib": deflateSync(bsonSave()),
    "save.zst": zstdCompressSync(cbor(SAVE)),
    "save.lz4": lz4Stored(msgpack(SAVE)),
    "save.deflate": deflateRawSync(msgpack(SAVE)),
    "save.br": brotliCompressSync(msgpack(SAVE)),
    "packet.bin": Buffer.concat([
      Buffer.from("HDR1"),
      protobufSave(),
      Buffer.from("TAIL"),
    ]),
    "r.0.0.mca": regionFile(),
    "noise.bin": Buffer.from(
      "\x00\x01\x02 PlayerName=Ana; score=99 \xff\xfe",
      "latin1",
    ),
  });
  for (const [name, bytes] of Object.entries(files))
    await writeFile(path(name), bytes);
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as DataBlobReport;
};
const rows = (report: DataBlobReport) =>
  report.tree.map(({ path: at, type, value }) => [at, type, value]);

describe("structured formats", () => {
  it("decodes schema-less protobuf like protoc --decode_raw, with other readings", async () => {
    const report = await inspect({ path: path("save.pb") });
    expect(report.format).toEqual({
      name: "protobuf",
      forced: false,
      region_chunk: null,
    });
    expect(rows(report)).toEqual([
      ["$", "message", null],
      ["$.1", "string", "Ana"],
      ["$.2", "varint", "42"],
      ["$.3", "varint", "18446744073709551609"],
      ["$.4", "varint", "5"],
      ["$.7", "fixed32", "1056964608"],
      ["$.9[0]", "message", null],
      ["$.9[0].1", "string", "sword"],
      ["$.9[0].2", "varint", "1"],
      ["$.9[1]", "message", null],
      ["$.9[1].1", "string", "potion"],
      ["$.9[1].2", "varint", "12"],
      ["$.12", "group", null],
      ["$.12.13", "varint", "5"],
      ["$.12.14", "varint", "9"],
      ["$.10", "bytes", "0102ac02"],
    ]);
    const byPath = new Map(report.tree.map((row) => [row.path, row]));
    expect(byPath.get("$.3")?.alternatives).toMatchObject({ int64: "-7" });
    expect(byPath.get("$.4")?.alternatives).toMatchObject({ sint64: "-3" });
    expect(byPath.get("$.7")?.alternatives).toMatchObject({
      float: "0.5",
      hex: "0x3f000000",
    });
    expect(byPath.get("$.10")?.alternatives).toEqual({
      packed_varints: "1, 2, 300",
    });
    expect(byPath.get("$.1")).toMatchObject({
      offset: 0,
      length: 5,
      depth: 1,
      key: 1,
    });
  });

  it("decodes MessagePack, CBOR and BSON into the same shape", async () => {
    const expected: [string, string][] = [
      ["$.player", "Ana"],
      ["$.level", "42"],
      ["$.gold", "123456789012"],
      ["$.ratio", "0.5"],
      ["$.alive", "true"],
      ["$.items[1].name", "potion"],
      ["$.items[1].count", "12"],
      ["$.blob", "00ff"],
    ];
    for (const [name, format] of [
      ["save.msgpack", "msgpack"],
      ["save.cbor", "cbor"],
      ["save.bson", "bson"],
    ] as const) {
      const report = await inspect({ path: path(name), limit: 1000 });
      expect(report.format.name, name).toBe(format);
      const values = new Map(
        report.tree.map(({ path: at, value }) => [at, value]),
      );
      for (const [at, value] of expected)
        expect(values.get(at), `${name} ${at}`).toBe(value);
    }
    const bsonReport = await inspect({
      path: path("save.bson"),
      query: "objectid",
    });
    expect(bsonReport.tree).toMatchObject([
      { path: "$._id", value: "5f43a1b2c3d4e5f601234567" },
    ]);
  });

  it("decodes Java and Bedrock NBT and JSON", async () => {
    const java = await inspect({ path: path("level.dat") });
    expect(java.layers).toEqual([
      {
        kind: "gzip",
        input_bytes: files["level.dat"]?.length,
        output_bytes: nbtSave().length,
      },
    ]);
    expect(java.format.name).toBe("nbt");
    expect(rows(java).slice(0, 5)).toEqual([
      ["$", "compound", null],
      ["$.Data", "compound", null],
      ["$.Data.LevelName", "string", "Ana's World"],
      ["$.Data.Time", "long", "24000"],
      ["$.Data.SpawnX", "int", "-120"],
    ]);
    const bedrock = await inspect({ path: path("bedrock.dat"), limit: 4 });
    expect(bedrock.format.name).toBe("nbt-le");
    expect(rows(bedrock)).toEqual(rows(java).slice(0, 4));
    const json = await inspect({ path: path("save.json"), view: "strings" });
    expect(json.format.name).toBe("json");
    expect(json.strings.map(({ path: at, value }) => [at, value])).toEqual([
      ["$.player", "Ana"],
    ]);
  });
});

describe("layers, ranges and selections", () => {
  it("removes encodings and compression it can detect", async () => {
    const cases: [string, string[], string][] = [
      ["save.b64", ["base64", "gzip"], "msgpack"],
      ["save.hex", ["hex"], "protobuf"],
      ["save.zlib", ["zlib"], "bson"],
      ["save.zst", ["zstd"], "cbor"],
      ["save.lz4", ["lz4"], "msgpack"],
    ];
    for (const [name, layers, format] of cases) {
      const report = await inspect({ path: path(name), limit: 1 });
      expect(
        [report.layers.map(({ kind }) => kind), report.format.name],
        name,
      ).toEqual([layers, format]);
    }
  });

  it("applies named layers, formats and byte ranges", async () => {
    const deflate = await inspect({
      path: path("save.deflate"),
      layers: ["deflate"],
      limit: 1,
    });
    expect(deflate.format.name).toBe("msgpack");
    const brotli = await inspect({
      path: path("save.br"),
      layers: ["brotli"],
      format: "msgpack",
      limit: 1,
    });
    expect(brotli.format).toMatchObject({ name: "msgpack", forced: true });
    const packet = await inspect({
      path: path("packet.bin"),
      range_offset: 4,
      range_length: protobufSave().length,
      limit: 3,
    });
    expect(packet.range).toEqual({ offset: 4, length: protobufSave().length });
    expect(packet.format.name).toBe("protobuf");
  });

  it("lists a subtree to a depth, and matches queries", async () => {
    const items = await inspect({
      path: path("save.msgpack"),
      node: "$.items",
      max_depth: 1,
    });
    expect(items.tree.map(({ path: at }) => at)).toEqual([
      "$.items",
      "$.items[0]",
      "$.items[1]",
    ]);
    const query = await inspect({ path: path("save.pb"), query: "potion" });
    expect(query.tree.map(({ path: at }) => at)).toEqual(["$.9[1].1"]);
  });

  it("reads Minecraft region files and one chunk's NBT", async () => {
    const region = await inspect({ path: path("r.0.0.mca") });
    expect(region.format.name).toBe("mca");
    expect(
      region.tree.map(({ path: at, type, value }) => [
        at,
        type,
        value?.split(" ").slice(0, 3).join(" "),
      ]),
    ).toEqual([
      ["$", "region", undefined],
      ["$[0]", "chunk", "x=0 z=0 zlib"],
      ["$[33]", "chunk", "x=1 z=1 zlib"],
    ]);
    const chunk = await inspect({
      path: path("r.0.0.mca"),
      region_chunk: 33,
      node: "$.Data.Players[1]",
    });
    expect(chunk.format).toEqual({
      name: "nbt",
      forced: false,
      region_chunk: 33,
    });
    expect(rows(chunk)).toEqual([
      ["$.Data.Players[1]", "compound", null],
      ["$.Data.Players[1].Name", "string", "Bo"],
      ["$.Data.Players[1].Health", "short", "7"],
    ]);
  });

  it("falls back to printable strings, and refuses impossible selections", async () => {
    const noise = await inspect({ path: path("noise.bin"), view: "strings" });
    expect(noise.format.name).toBe("raw");
    expect(noise.candidates.every(({ ok }) => !ok)).toBe(true);
    expect(noise.strings).toEqual([
      { path: "@3", offset: 3, value: " PlayerName=Ana; score=99 " },
    ]);
    for (const [input, field] of [
      [{ path: path("save.pb"), node: "$.99" }, "node"],
      [{ path: path("save.pb"), range_offset: 9999 }, "range_offset"],
      [
        { path: path("save.pb"), range_offset: 4, range_length: 9999 },
        "range_length",
      ],
      [{ path: path("save.pb"), region_chunk: 1 }, "region_chunk"],
      [{ path: path("r.0.0.mca"), region_chunk: 5 }, "region_chunk"],
    ] as const)
      expect(await service.inspect(input), field).toMatchObject({
        ok: false,
        error: { issues: [{ path: [field] }] },
      });
    expect(
      await service.inspect({ path: path("save.json"), format: "bson" }),
    ).toMatchObject({
      ok: false,
      error: {
        issues: [
          {
            path: ["path"],
            message: expect.stringContaining("Not a readable blob"),
          },
        ],
      },
    });
  });
});

const PROTOC = process.env["REA_VERIFY_PROTOC"];
const PYTHON = process.env["REA_VERIFY_BLOB_PYTHON"];
const LZ4 = process.env["REA_VERIFY_LZ4_BIN"];
const ZSTD = process.env["REA_VERIFY_ZSTD_BIN"];
const NBT_DIR = process.env["REA_VERIFY_NBT_DIR"];

/** Every tree row of a file, paging past the 1000-row limit. */
const allRows = async (input: Record<string, unknown>) => {
  const rows: DataBlobReport["tree"] = [];
  for (let offset = 0; ; offset += 1000) {
    const report = await inspect({ ...input, offset, limit: 1000 });
    rows.push(...report.tree);
    if (offset + 1000 >= report.page.total) return { report, rows };
  }
};

describe.skipIf(PROTOC === undefined)(
  "protobuf decoded as protoc --decode_raw decodes it",
  () => {
    it("matches protoc on random messages and protoc's own encodings", async () => {
      const { execFile, spawnSync } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const { protocText, random, randomMessage } =
        await import("../../../support/blob/blobReferences.js");
      const decodeRaw = (bytes: Buffer) =>
        spawnSync(PROTOC ?? "", ["--decode_raw"], {
          input: bytes,
          encoding: "latin1",
          cwd: root,
        }).stdout;
      const next = random(20261016);
      for (let index = 0; index < 300; index += 1) {
        const bytes = randomMessage(next);
        if (bytes.length === 0) continue;
        await writeFile(path("random.pb"), bytes);
        const { rows } = await allRows({
          path: path("random.pb"),
          format: "protobuf",
        });
        expect(protocText(rows), `message ${String(index)}`).toBe(
          decodeRaw(bytes),
        );
      }
      // A FileDescriptorSet and a message, both written by protoc itself.
      await writeFile(
        path("save.proto"),
        'syntax = "proto2";\nmessage Item { optional string name = 1; optional int32 count = 2; }\nmessage Save { optional string player = 1; optional int32 level = 2; repeated Item items = 9; repeated int32 packed = 10 [packed = true]; optional double precise = 8; }\n',
      );
      await promisify(execFile)(
        PROTOC ?? "",
        ["-I", root, `--descriptor_set_out=${path("set.pb")}`, "save.proto"],
        { cwd: root },
      );
      const encoded = spawnSync(
        PROTOC ?? "",
        ["-I", root, "--encode=Save", "save.proto"],
        {
          input:
            'player: "Ana" level: 42 items { name: "sword" count: 1 } packed: [1, 300] precise: 3.5',
          cwd: root,
        },
      ).stdout;
      await writeFile(path("encoded.pb"), encoded);
      const { readFile } = await import("node:fs/promises");
      for (const name of ["set.pb", "encoded.pb"]) {
        const { rows } = await allRows({
          path: path(name),
          format: "protobuf",
        });
        expect(protocText(rows), name).toBe(
          decodeRaw(await readFile(path(name))),
        );
      }
    }, 600_000);
  },
);

describe.skipIf(PYTHON === undefined)(
  "MessagePack, CBOR and BSON decoded as their reference libraries decode them",
  () => {
    it("matches msgpack, cbor2 and bson on random values", async () => {
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const { readFile, readdir } = await import("node:fs/promises");
      const { canonical, PYTHON_SAMPLES } =
        await import("../../../support/blob/blobReferences.js");
      await writeFile(path("samples.py"), PYTHON_SAMPLES);
      const out = path("python-samples");
      await promisify(execFile)(
        PYTHON ?? "",
        ["-I", path("samples.py"), out, "200", "7"],
        { cwd: root },
      );
      const names = (await readdir(out)).filter((name) =>
        /\.(msgpack|cbor|bson)$/u.test(name),
      );
      expect(names.length).toBeGreaterThan(500);
      for (const name of names) {
        const format = name.split(".").at(-1);
        const { rows } = await allRows({ path: join(out, name), format });
        expect(canonical(rows), name).toEqual(
          JSON.parse(await readFile(join(out, `${name}.json`), "utf8")),
        );
      }
    }, 600_000);
  },
);

describe.skipIf(LZ4 === undefined && ZSTD === undefined)(
  "layers written by the lz4 and zstd tools",
  () => {
    it("decodes linked LZ4 blocks and zstd frames", async () => {
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      // Over 64 KiB, so 64 KiB linked LZ4 blocks reach back into earlier ones.
      const big = msgpack(
        Array.from(
          { length: 4000 },
          (_, index) =>
            [`key${String(index)}`, `value ${String(index * 7)}`] as const,
        ),
      );
      await writeFile(path("big.msgpack"), big);
      const tools: [string | undefined, string[], string][] = [
        [
          LZ4,
          ["-q", "-f", "-B4", "-BD", path("big.msgpack"), path("big.lz4")],
          "big.lz4",
        ],
        [
          LZ4,
          [
            "-q",
            "-f",
            "-9",
            "--content-size",
            path("big.msgpack"),
            path("big.hc.lz4"),
          ],
          "big.hc.lz4",
        ],
        [
          ZSTD,
          ["-q", "-f", "-19", path("big.msgpack"), "-o", path("big.zst")],
          "big.zst",
        ],
      ];
      for (const [bin, args, name] of tools) {
        if (bin === undefined) continue;
        await promisify(execFile)(bin, args, { cwd: root });
        const report = await inspect({ path: path(name), limit: 1 });
        expect(report.format.name, name).toBe("msgpack");
        expect(report.payload.bytes, name).toBe(big.length);
        expect(report.summary.nodes, name).toBe(4001);
      }
    }, 120_000);
  },
);

/**
 * Every chunk the header lists as readable decodes as NBT, except in
 * twoolie/NBT's regiontest.mca, whose damaged chunks its tests document.
 * It uses type 0 for uncompressed and 3 as unknown; Minecraft now defines 3
 * as uncompressed, so chunk 2 is refused and chunk 11 is read but not NBT.
 */
const regionHolds = async (file: string, report: DataBlobReport) => {
  const damaged = file.endsWith("regiontest.mca");
  const chunks = report.tree.slice(1);
  const unreadable = chunks
    .filter(({ value }) => value?.includes("unreadable"))
    .map(({ key }) => key);
  expect(unreadable, file).toEqual(damaged ? [2, 13, 14, 15, 36, 40] : []);
  for (const { key } of chunks) {
    if (unreadable.includes(key)) continue;
    const chunk = await service.inspect({
      path: file,
      region_chunk: key,
      limit: 1,
    });
    expect(chunk.ok, `${file} chunk ${String(key)}`).toBe(
      !(damaged && [3, 11, 37].includes(Number(key))),
    );
  }
};

describe.skipIf(NBT_DIR === undefined)("real NBT and region files", () => {
  it("reads every file, and bigtest.nbt as its specification lists it", async () => {
    const { readdir } = await import("node:fs/promises");
    const entries = await readdir(NBT_DIR ?? "", {
      recursive: true,
      withFileTypes: true,
    });
    const files = entries
      .filter(
        (entry) => entry.isFile() && /\.(nbt|dat|mca|mcr)$/u.test(entry.name),
      )
      .map((entry) => join(entry.parentPath, entry.name));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const report = await inspect({ path: file, limit: 1000 });
      if (/\.mc[ar]$/u.test(file)) {
        expect(report.format.name, file).toBe("mca");
        await regionHolds(file, report);
        continue;
      }
      // Querz's suite keeps deliberately broken files, named for the fault.
      if (/(invalid_|max_depth)/u.test(file)) {
        expect(["nbt", "nbt-le"], file).not.toContain(report.format.name);
        continue;
      }
      expect(["nbt", "nbt-le"], file).toContain(report.format.name);
      if (file.endsWith("bigtest.nbt")) {
        const values = new Map(report.tree.map((row) => [row.path, row.value]));
        expect(values.get("$.longTest")).toBe("9223372036854775807");
        expect(values.get("$.shortTest")).toBe("32767");
        expect(values.get("$.stringTest")).toBe(
          "HELLO WORLD THIS IS A TEST STRING ÅÄÖ!",
        );
        expect(values.get("$.intTest")).toBe("2147483647");
        expect(values.get('$["nested compound test"].ham.name')).toBe("Hampus");
        expect(values.get('$["listTest (long)"][4]')).toBe("15");
        expect(values.get('$["listTest (compound)"][1].name')).toBe(
          "Compound tag #1",
        );
      }
    }
  }, 300_000);
});
