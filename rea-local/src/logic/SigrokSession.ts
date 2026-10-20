import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import { streamChunkToBuffer } from "../artifacts/StreamBytes.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import type { LogicCapture } from "../domain/logic/logicCapture.js";

/** A session file whose archive, metadata or sample chunks are unusable. */
export class SigrokSessionError extends Error {}

/** Largest combined logic or analog sample data read from one session. */
export const MAX_SESSION_SAMPLE_BYTES = 512 * 1024 * 1024;

export interface SigrokChannel {
  readonly name: string;
  /** 1-based probe number from the metadata. */
  readonly index: number;
}

export interface SigrokSession {
  readonly sigrokVersion: string | null;
  readonly samplerate: number;
  readonly unitsize: number;
  readonly logicChannels: readonly SigrokChannel[];
  readonly analogChannels: readonly SigrokChannel[];
  readonly logic: Buffer;
  readonly analog: ReadonlyMap<number, Float32Array>;
}

const fail = (message: string): never => {
  throw new SigrokSessionError(message);
};

const UNITS: Readonly<Record<string, number>> = {
  Hz: 1,
  kHz: 1e3,
  MHz: 1e6,
  GHz: 1e9,
};

/** sigrok writes rates such as "200 kHz", "1 MHz" or a bare integer. */
export const parseSamplerate = (value: string): number => {
  const match = /^(\d+(?:\.\d+)?)\s*(Hz|kHz|MHz|GHz)?$/u.exec(value.trim());
  const rate = Number(match?.[1]) * (UNITS[match?.[2] ?? "Hz"] ?? 1);
  return match !== null && rate > 0
    ? rate
    : fail(`Unsupported samplerate "${value}".`);
};

/** INI sections of the `metadata` entry; keys keep sigrok's spelling. */
const parseMetadata = (text: string) => {
  const sections = new Map<string, Map<string, string>>();
  let current: Map<string, string> | undefined;
  for (const raw of text.split(/\r?\n/u)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith(";") || line.startsWith("#"))
      continue;
    const section = /^\[(.+)\]$/u.exec(line);
    if (section !== null) {
      current = new Map();
      sections.set(section[1] ?? "", current);
      continue;
    }
    const equals = line.indexOf("=");
    if (equals < 0 || current === undefined)
      fail(`Malformed metadata line: ${line}`);
    current?.set(line.slice(0, equals).trim(), line.slice(equals + 1).trim());
  }
  return sections;
};

const channels = (device: ReadonlyMap<string, string>, prefix: string) =>
  [...device]
    .flatMap(([key, name]) => {
      const index = new RegExp(`^${prefix}(\\d+)$`, "u").exec(key)?.[1];
      return index === undefined ? [] : [{ name, index: Number(index) }];
    })
    .sort((left, right) => left.index - right.index);

const readEntry = async (
  reader: ZipArtifactReader,
  entry: ArtifactEntry,
  budget: { remaining: number },
  signal?: AbortSignal,
): Promise<Buffer> => {
  const parts: Buffer[] = [];
  for await (const chunk of await reader.open(entry, signal)) {
    const bytes = streamChunkToBuffer(chunk);
    budget.remaining -= bytes.length;
    if (budget.remaining < 0)
      fail(
        `Session sample data exceeds ${String(MAX_SESSION_SAMPLE_BYTES)} bytes.`,
      );
    parts.push(bytes);
  }
  return Buffer.concat(parts);
};

/** Chunks named `<base>-<n>` (or `<base>` alone in version 1) in order. */
const chunksOf = (
  entries: ReadonlyMap<string, ArtifactEntry>,
  base: string,
): ArtifactEntry[] =>
  [...entries]
    .flatMap(([path, entry]) => {
      if (path === base) return [{ entry, order: 0 }];
      const order = path.startsWith(`${base}-`)
        ? /^\d+$/u.exec(path.slice(base.length + 1))?.[0]
        : undefined;
      return order === undefined ? [] : [{ entry, order: Number(order) }];
    })
    .sort((left, right) => left.order - right.order)
    .map(({ entry }) => entry);

/** Read a sigrok session (.sr) archive's first device. */
export const readSigrokSession = async (
  path: string,
  signal?: AbortSignal,
): Promise<SigrokSession> => {
  const reader = new ZipArtifactReader(path, "zip", 1024 * 1024);
  try {
    const entries = new Map<string, ArtifactEntry>();
    for await (const entry of reader.entries(signal))
      if (entry.kind === "file") entries.set(entry.path, entry);
    const budget = { remaining: MAX_SESSION_SAMPLE_BYTES };
    const metadataEntry =
      entries.get("metadata") ?? fail("The session has no metadata entry.");
    const sections = parseMetadata(
      (await readEntry(reader, metadataEntry, budget, signal)).toString("utf8"),
    );
    const device =
      sections.get("device 1") ?? fail("The metadata has no [device 1].");
    const unitsize = Number(device.get("unitsize") ?? "1");
    if (!Number.isInteger(unitsize) || unitsize < 1 || unitsize > 8)
      fail(`Unsupported unitsize ${String(device.get("unitsize"))}.`);
    const logicChannels = channels(device, "probe");
    if (logicChannels.some(({ index }) => index > unitsize * 8))
      fail("A probe number exceeds the sample width.");
    const capture = device.get("capturefile");
    const readAll = async (base: string) => {
      const parts: Buffer[] = [];
      for (const entry of chunksOf(entries, base))
        parts.push(await readEntry(reader, entry, budget, signal));
      return Buffer.concat(parts);
    };
    const logic =
      capture === undefined ? Buffer.alloc(0) : await readAll(capture);
    if (logic.length % unitsize !== 0)
      fail("Logic data is not a whole number of samples.");
    const analogChannels = channels(device, "analog");
    const analog = new Map<number, Float32Array>();
    for (const channel of analogChannels) {
      const bytes = await readAll(`analog-1-${String(channel.index)}`);
      if (bytes.length % 4 !== 0)
        fail(`Analog channel ${channel.name} is not whole float32 samples.`);
      const samples = new Float32Array(bytes.length / 4);
      for (let index = 0; index < samples.length; index += 1)
        samples[index] = bytes.readFloatLE(index * 4);
      analog.set(channel.index, samples);
    }
    return {
      sigrokVersion: sections.get("global")?.get("sigrok version") ?? null,
      samplerate: parseSamplerate(
        device.get("samplerate") ?? fail("The device has no samplerate."),
      ),
      unitsize,
      logicChannels,
      analogChannels,
      logic,
      analog,
    };
  } finally {
    await reader.close();
  }
};

/** Complete runs (between two edges) by length in samples. */
const MAX_RUN_LENGTHS = 4096;

/**
 * Mean length of runs shorter than 1.5 shortest runs: one bit time even when
 * the samplerate is not a multiple of the bit rate.
 */
const unitRun = (runs: ReadonlyMap<number, number>): number | null => {
  if (runs.size === 0) return null;
  const shortest = Math.min(...runs.keys());
  let samples = 0;
  let count = 0;
  for (const [length, seen] of runs)
    if (length < shortest * 1.5) {
      samples += length * seen;
      count += seen;
    }
  return samples / count;
};

/** Edge statistics for one logic channel over every sample. */
export const channelStatistics = (
  session: SigrokSession,
  channel: SigrokChannel,
): LogicCapture["channels"][number] => {
  const { logic, unitsize, samplerate } = session;
  const samples = logic.length / unitsize;
  const bit = channel.index - 1;
  const offset = Math.floor(bit / 8);
  const mask = 1 << (bit % 8);
  const level = (sample: number): 0 | 1 =>
    ((logic[sample * unitsize + offset] ?? 0) & mask) === 0 ? 0 : 1;
  let previous = samples === 0 ? 0 : level(0);
  let transitions = 0;
  let firstEdge = -1;
  let lastEdge = -1;
  let high = 0;
  const runs = new Map<number, number>();
  for (let sample = 0; sample < samples; sample += 1) {
    const current = level(sample);
    high += current;
    if (current === previous) continue;
    const run = sample - lastEdge;
    if (lastEdge >= 0 && (runs.has(run) || runs.size < MAX_RUN_LENGTHS))
      runs.set(run, (runs.get(run) ?? 0) + 1);
    if (firstEdge < 0) firstEdge = sample;
    lastEdge = sample;
    transitions += 1;
    previous = current;
  }
  const shortest = runs.size === 0 ? null : Math.min(...runs.keys());
  const unit = unitRun(runs);
  return {
    name: channel.name,
    index: channel.index,
    initial_level: samples === 0 ? 0 : level(0),
    final_level: samples === 0 ? 0 : level(samples - 1),
    transitions,
    first_transition_s: firstEdge < 0 ? null : firstEdge / samplerate,
    high_fraction: samples === 0 ? 0 : high / samples,
    shortest_pulse_s: shortest === null ? null : shortest / samplerate,
    estimated_bit_rate: unit === null ? null : Math.round(samplerate / unit),
  };
};

export const analogStatistics = (
  channel: SigrokChannel,
  samples: Float32Array,
): LogicCapture["analog"][number] => {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  let sum = 0;
  for (const value of samples) {
    min = Math.min(min, value);
    max = Math.max(max, value);
    sum += value;
  }
  const empty = samples.length === 0;
  return {
    name: channel.name,
    index: channel.index,
    samples: samples.length,
    min: empty ? 0 : min,
    max: empty ? 0 : max,
    mean: empty ? 0 : sum / samples.length,
  };
};
