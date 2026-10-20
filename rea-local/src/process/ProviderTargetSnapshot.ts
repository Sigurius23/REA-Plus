import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, rm, type FileHandle } from "node:fs/promises";
import { extname, join } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import type { JsonValue } from "../domain/jsonValue.js";
import {
  AnalysisArtifactChangedError,
  AnalysisAccessDeniedError,
} from "../domain/analysisErrorCore.js";
import { windowsPrivateRuntime } from "../windows/WindowsPrivateRuntime.js";

/** Immutable target copy admitted to one provider-owned private runtime root. */
export interface ProviderTargetSnapshot {
  readonly path: string;
  readonly sha256: string;
  readonly admission?: JsonValue;
}

/** Copy one target and require its bytes to match the parsed target identity. */
export const createProviderTargetSnapshot = async (
  sourcePath: string,
  runtimeRoot: string,
  expectedSha256: string,
  options: {
    /** Provider display name used in admission failures, such as "Ghidra". */
    readonly providerName: string;
    readonly signal?: AbortSignal;
    readonly platform?: NodeJS.Platform;
  },
): Promise<ProviderTargetSnapshot> => {
  const providerName = options.providerName;
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256))
    throw new TypeError(`${providerName} target SHA-256 commitment is invalid`);
  const suffix = safeExtension(sourcePath);
  const snapshotPath = join(
    runtimeRoot,
    `target-${expectedSha256.slice(0, 12)}${suffix}`,
  );
  if ((options.platform ?? process.platform) === "win32") {
    const observed = await windowsPrivateRuntime(runtimeRoot).snapshot(
      sourcePath,
      `target-${expectedSha256.slice(0, 12)}${suffix}`,
      options.signal,
    );
    if (observed.sha256 !== expectedSha256)
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        `${providerName} target snapshot digest mismatch: expected ${expectedSha256}, observed ${observed.sha256}`,
      );
    return {
      path: snapshotPath,
      sha256: observed.sha256,
      admission: { source: observed.source, snapshot: observed.snapshot },
    };
  }
  let source: FileHandle | undefined;
  let destination: FileHandle | undefined;
  try {
    source = await openSnapshotSource(sourcePath, providerName);
    if (!(await source.stat()).isFile())
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        `The selected ${providerName} source is no longer a regular file`,
      );
    destination = await open(snapshotPath, "wx", 0o600);
    await destination.chmod(0o600);
    const hash = createHash("sha256");
    const digest = new Transform({
      transform(chunk: unknown, _encoding, done) {
        if (!Buffer.isBuffer(chunk)) {
          done(
            new TypeError(`${providerName} snapshot stream must contain bytes`),
          );
          return;
        }
        hash.update(chunk);
        done(null, chunk);
      },
    });
    await pipeline(
      source.createReadStream(),
      digest,
      destination.createWriteStream(),
      options.signal === undefined ? {} : { signal: options.signal },
    );
    const observedSha256 = hash.digest("hex");
    if (observedSha256 !== expectedSha256)
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        `${providerName} target snapshot digest mismatch: expected ${expectedSha256}, observed ${observedSha256}`,
      );
    return { path: snapshotPath, sha256: observedSha256 };
  } catch (cause: unknown) {
    if (destination !== undefined)
      await rm(snapshotPath, { force: true }).catch((cause: unknown) => {
        // best-effort cleanup: snapshot removal must not mask the copy failure.
        void cause;
      });
    throw cause;
  } finally {
    await Promise.all([source?.close(), destination?.close()]);
  }
};

const openSnapshotSource = async (
  path: string,
  providerName: string,
): Promise<FileHandle> => {
  try {
    // A path replaced by a FIFO must not block startup before its type is checked.
    return await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  } catch (cause: unknown) {
    const code =
      cause instanceof Error && "code" in cause ? cause.code : undefined;
    if (code === "EACCES" || code === "EPERM")
      throw new AnalysisAccessDeniedError("open_binary", path, code, { cause });
    if (code === "ENOENT" || code === "ENOTDIR" || code === "ELOOP")
      throw new AnalysisArtifactChangedError(
        "open_binary",
        path,
        `The selected ${providerName} source could not be opened (${code})`,
        { cause },
      );
    throw cause;
  }
};

const safeExtension = (path: string): string => {
  const extension = extname(path);
  return /^\.[A-Za-z0-9]{1,12}$/u.test(extension) ? extension : ".bin";
};
