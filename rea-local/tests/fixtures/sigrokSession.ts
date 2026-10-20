import { crc32 } from "node:zlib";

/**
 * Deterministic sigrok session (.sr, format version 2) sampled at 1 MHz:
 * D0 carries UART 8N1 at 115200 baud, D2-D4 an SPI mode-0 transfer at
 * 100 kHz (CLK, MOSI, CS#), D1 stays low, and analog A0 is a ramp.
 * The logic data is split over two chunks, as sigrok writes long captures.
 */
export const SIGROK_FIXTURE = Object.freeze({
  samplerate: 1_000_000,
  baud: 115_200,
  uartText: "Hello REA+\r\n",
  spiBytes: [0x9f, 0xef, 0x40, 0x18],
  channels: ["UART_TX", "IDLE", "CLK", "MOSI", "CS"],
  analog: [0, 0.5, 1, 1.5, 2, 2.5, 3, 3.5],
});

const F = SIGROK_FIXTURE;

/** Per-channel levels; every channel has the same sample count. */
const waveforms = (): number[][] => {
  const tx: number[] = [];
  const clk: number[] = [];
  const mosi: number[] = [];
  const cs: number[] = [];
  const hold = (
    samples: number,
    levels: readonly [number, number, number, number],
  ) => {
    for (let index = 0; index < samples; index += 1) {
      tx.push(levels[0]);
      clk.push(levels[1]);
      mosi.push(levels[2]);
      cs.push(levels[3]);
    }
  };
  hold(200, [1, 0, 0, 1]);
  const bits = [...Buffer.from(F.uartText, "latin1")].flatMap((byte) => [
    0,
    ...Array.from({ length: 8 }, (_, bit) => (byte >> bit) & 1),
    1,
  ]);
  const uartSamples = Math.round((bits.length / F.baud) * F.samplerate);
  for (let sample = 0; sample < uartSamples; sample += 1)
    hold(1, [bits[Math.floor((sample * F.baud) / F.samplerate)] ?? 1, 0, 0, 1]);
  hold(100, [1, 0, 0, 1]);
  hold(10, [1, 0, 0, 0]);
  for (const byte of F.spiBytes)
    for (let bit = 7; bit >= 0; bit -= 1) {
      const level = (byte >> bit) & 1;
      hold(5, [1, 0, level, 0]);
      hold(5, [1, 1, level, 0]);
    }
  hold(10, [1, 0, 0, 0]);
  hold(100, [1, 0, 0, 1]);
  const idle = tx.map(() => 0);
  return [tx, idle, clk, mosi, cs];
};

const u16 = (value: number) => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
};
const u32 = (value: number) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value >>> 0);
  return bytes;
};

/** A stored (uncompressed) ZIP archive with one central directory. */
export const createStoredZip = (
  files: readonly (readonly [name: string, data: Buffer])[],
): Buffer => {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, data] of files) {
    const fileName = Buffer.from(name, "utf8");
    const checksum = crc32(data);
    const common = Buffer.concat([
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(0x21),
      u32(checksum),
      u32(data.length),
      u32(data.length),
      u16(fileName.length),
      u16(0),
    ]);
    const local = Buffer.concat([u32(0x04034b50), common, fileName, data]);
    central.push(
      Buffer.concat([
        u32(0x02014b50),
        u16(20),
        common,
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(offset),
        fileName,
      ]),
    );
    locals.push(local);
    offset += local.length;
  }
  const directory = Buffer.concat(central);
  return Buffer.concat([
    ...locals,
    directory,
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(files.length),
    u16(files.length),
    u32(directory.length),
    u32(offset),
    u16(0),
  ]);
};

/** Build the session; every call returns an identical buffer. */
export const createSigrokSession = (): Buffer => {
  const channels = waveforms();
  const samples = channels[0]?.length ?? 0;
  const logic = Buffer.alloc(samples);
  for (let sample = 0; sample < samples; sample += 1)
    logic[sample] = channels.reduce(
      (word, levels, index) => word | ((levels[sample] ?? 0) << index),
      0,
    );
  const analog = Buffer.alloc(F.analog.length * 4);
  F.analog.forEach((value, index) => analog.writeFloatLE(value, index * 4));
  const metadata = [
    "[global]",
    "sigrok version=0.5.2",
    "",
    "[device 1]",
    "capturefile=logic-1",
    `total probes=${String(F.channels.length)}`,
    "samplerate=1 MHz",
    "total analog=1",
    ...F.channels.map((name, index) => `probe${String(index + 1)}=${name}`),
    `analog${String(F.channels.length + 1)}=A0`,
    "unitsize=1",
    "",
  ].join("\n");
  const half = Math.floor(samples / 2);
  return createStoredZip([
    ["version", Buffer.from("2")],
    ["metadata", Buffer.from(metadata)],
    ["logic-1-2", logic.subarray(half)],
    ["logic-1-1", logic.subarray(0, half)],
    [`analog-1-${String(F.channels.length + 1)}-1`, analog],
  ]);
};
