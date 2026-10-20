import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";
import { isAbsolute } from "node:path";

import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type {
  InspectLogicCaptureInput,
  LogicAnnotation,
  LogicCapture,
} from "../domain/logic/logicCapture.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];

export const SIGROK_LIMITS = {
  timeoutMs: 300_000,
  /** Complete stdout/stderr retained per sigrok-cli process. */
  outputBytes: 128 * 1024 * 1024,
  /** Bytes of each hex byte stream returned inline. */
  byteStreamBytes: 64 * 1024,
} as const;

/** sigrok-cli could not run the requested stack; its stderr explains why. */
export class SigrokDecodeRejected extends Error {}

/** sigrok-cli is missing, unsupported or failed to start. */
export class SigrokUnavailable extends Error {}

export interface SigrokProfile {
  readonly path: string;
  readonly sha256: string;
  readonly version: string;
  readonly libsigrokdecode: string | null;
}

const ANNOTATION_LINE = /^(\d+)-(\d+) ([A-Za-z0-9_]+-\d+): (.*)$/u;

/** Run one owned sigrok-cli; any stderr is a rejection, since 0.7 exits 0 on decoder errors. */
export const runSigrok = async (
  executable: string,
  args: readonly string[],
  options: {
    readonly cwd?: string;
    readonly signal?: AbortSignal;
    readonly launcher?: Launcher;
    readonly environment: Readonly<NodeJS.ProcessEnv>;
  },
): Promise<string> => {
  const snapshot = await runOwnedCommand(
    {
      command: executable,
      arguments: args,
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      runId: `rea-sigrok-${randomUUID()}`,
      hostEnvironment: options.environment,
    },
    {
      timeoutMs: SIGROK_LIMITS.timeoutMs,
      diagnosticBytes: SIGROK_LIMITS.outputBytes,
      acceptNonZeroExit: true,
    },
    {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.launcher === undefined ? {} : { launcher: options.launcher }),
    },
  );
  const stderr = snapshot.stderr.text.trim();
  if (stderr.length > 0 || snapshot.exitCode !== 0)
    throw new SigrokDecodeRejected(
      stderr.length > 0
        ? stderr.slice(0, 4000)
        : `sigrok-cli exited with ${String(snapshot.exitCode)}.`,
    );
  return snapshot.stdout.text;
};

/** Resolve REA_SIGROK_CLI and require a 0.7 release. */
export const sigrokProfile = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: { readonly signal?: AbortSignal; readonly launcher?: Launcher },
): Promise<SigrokProfile> => {
  const configured = environment.REA_SIGROK_CLI ?? "";
  if (!isAbsolute(configured))
    throw new SigrokUnavailable(
      "Protocol decoding needs REA_SIGROK_CLI, the absolute path of sigrok-cli 0.7.",
    );
  const path = await realpath(configured);
  await access(path, constants.X_OK);
  const executable = await readStableArtifact(
    path,
    64 * 1024 * 1024,
    options.signal,
  );
  let banner: string;
  try {
    banner = await runSigrok(path, ["--version"], { ...options, environment });
  } catch (cause: unknown) {
    throw new SigrokUnavailable(
      `sigrok-cli --version failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  const version = /^sigrok-cli (0\.7\.\d+)$/mu.exec(banner)?.[1];
  if (version === undefined)
    throw new SigrokUnavailable(
      `REA_SIGROK_CLI reported "${banner.split("\n")[0] ?? ""}"; expected sigrok-cli 0.7.`,
    );
  return {
    path,
    sha256: executable.sha256,
    version,
    libsigrokdecode: /^- libsigrokdecode (\S+?)\//mu.exec(banner)?.[1] ?? null,
  };
};

/** The -P argument: stacked decoders joined by commas, options by colons. */
export const decoderStack = (
  decoders: NonNullable<InspectLogicCaptureInput["decoders"]>,
): string =>
  decoders
    .map(({ id, channels, options }) =>
      [
        id,
        ...Object.entries(channels).map(([role, name]) => `${role}=${name}`),
        ...Object.entries(options).map(
          ([key, value]) => `${key}=${String(value)}`,
        ),
      ].join(":"),
    )
    .join(",");

/** Annotation classes from `sigrok-cli -P <id> --show`. */
export const parseDecoderClasses = (show: string) => {
  const lines = show.split("\n");
  const start = lines.indexOf("Annotation classes:");
  const classes: { id: string; description: string }[] = [];
  for (const line of start < 0 ? [] : lines.slice(start + 1)) {
    const match = /^- ([A-Za-z0-9_-]+): (.*)$/u.exec(line);
    if (match === null) break;
    classes.push({ id: match[1] ?? "", description: match[2] ?? "" });
  }
  return classes;
};

/** Parse `--protocol-decoder-samplenum` lines into annotations. */
export const parseAnnotations = (
  stdout: string,
  annotationClass: string | null,
  samplerate: number,
): LogicAnnotation[] =>
  stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => {
      const match = ANNOTATION_LINE.exec(line);
      if (match === null)
        throw new SigrokDecodeRejected(
          `Unexpected sigrok-cli output line: ${line.slice(0, 200)}`,
        );
      const start = Number(match[1]);
      const end = Number(match[2]);
      return {
        class: annotationClass,
        decoder: match[3] ?? "",
        start_sample: start,
        end_sample: end,
        start_s: start / samplerate,
        end_s: end / samplerate,
        text: match[4] ?? "",
      };
    });

/** Classes whose every annotation is one hex byte become byte streams. */
export const byteStream = (
  annotationClass: string,
  annotations: readonly LogicAnnotation[],
): NonNullable<LogicCapture["decode"]>["byte_streams"][number] | null => {
  if (
    annotations.length === 0 ||
    !annotations.every(({ text }) => /^[0-9A-Fa-f]{2}$/u.test(text))
  )
    return null;
  const bytes = Buffer.from(
    annotations.map(({ text }) => text).join(""),
    "hex",
  );
  const kept = bytes.subarray(0, SIGROK_LIMITS.byteStreamBytes);
  return {
    class: annotationClass,
    bytes: bytes.length,
    hex: kept.toString("hex"),
    text: new TextDecoder("utf-8").decode(kept),
    truncated: kept.length < bytes.length,
  };
};
