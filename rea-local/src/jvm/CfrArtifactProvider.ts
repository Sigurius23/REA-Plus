import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { JvmArtifactPort } from "../application/jvm/JvmArtifactPort.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  jvmArtifactSchema,
  type InspectJvmArtifactInput,
  type JvmArtifact,
} from "../domain/jvm/jvmArtifact.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { cfrFailure, withoutJvmEnvironmentNotices } from "./CfrFailures.js";
import {
  CFR_LIMITS,
  CFR_PROVIDER_IDENTITY,
  CFR_RELEASE,
} from "./CfrRelease.js";
import {
  isJvmClassFile,
  javaRelease,
  readJvmClassHeader,
  type JvmClassHeader,
} from "./JvmClassFile.js";
import { listJarClasses, topLevelClass } from "./JvmJarInventory.js";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];
type Runtime = Pick<PrivateRuntimeRoot, "path" | "close">;
type Phase = "configuration" | "artifact" | "producer";

const OPERATION = "inspect_jvm_artifact";
const FAILURE_MARKERS = [
  "Exception decompiling",
  "has failed to decompile",
  "Unable to fully structure code",
];
const LIMITATIONS = [
  "Java source is CFR 0.152's reconstruction from bytecode, not original source: local names, comments, generics and control-flow structure can differ, and CFR marks code it could not structure.",
  "CFR writes nested classes into their outermost class's source, so requesting Outer$Inner returns Outer's source.",
  "Bytecode is parsed, never loaded or executed. CFR and Java are trusted caller-supplied programs; their SHA-256 and version banners identify them, not publisher authenticity.",
  "JAR inventories omit META-INF entries (including multi-release copies) and module-info/package-info descriptors. Classes from other JARs are not resolved.",
];

interface ToolProfile {
  readonly jarPath: string;
  readonly jarSha256: string;
  readonly java: string;
}

interface SelectedClass {
  readonly name: string;
  readonly topLevel: string;
  readonly sha256: string;
  readonly header: JvmClassHeader;
}

/** Decompile explicitly selected JVM classes with caller-supplied CFR 0.152. */
export class CfrArtifactProvider implements JvmArtifactPort {
  readonly #pendingRoots = new Set<Runtime>();

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<Runtime> = () =>
      PrivateRuntimeRoot.create({ prefix: "rea-cfr-" }),
  ) {}

  /** Retry retained cleanup without discarding roots that still fail. */
  async close(): Promise<void> {
    const failures: { path: string; reason: string }[] = [];
    for (const root of this.#pendingRoots) {
      try {
        await root.close();
        this.#pendingRoots.delete(root);
      } catch (cause: unknown) {
        failures.push({
          path: root.path,
          reason: cause instanceof Error ? cause.message : String(cause),
        });
      }
    }
    if (failures.length > 0)
      throw new ProviderCleanupError(
        CFR_PROVIDER_IDENTITY.id,
        failures.map(({ path }) => path),
        { failures },
        { operation: OPERATION },
      );
  }

  async inspect(
    input: InspectJvmArtifactInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    let root: Runtime | undefined;
    let phase: Phase = "configuration";
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      await this.close();
      const profile = await this.#profile(signal);
      phase = "artifact";
      const selected = await readStableArtifact(
        input.path,
        CFR_LIMITS.inputBytes,
        signal,
      );
      const kind = artifactKind(selected.bytes);
      root = await this.createRuntime();
      const snapshot = join(
        root.path,
        kind === "class" ? "input.class" : "input.jar",
      );
      await writeFile(snapshot, selected.bytes, {
        flag: "wx",
        mode: 0o400,
        ...(signal === undefined ? {} : { signal }),
      });
      const { classes, chosen } =
        kind === "class"
          ? classInventory(input, selected)
          : await this.#jarInventory(input, snapshot, signal);
      phase = "configuration";
      const versions = await this.#versions(profile, root.path, signal);
      phase = "producer";
      const tops = [...new Set(chosen.map(({ topLevel }) => topLevel))];
      const args = [
        "-jar",
        profile.jarPath,
        snapshot,
        "--outputdir",
        "out",
        "--silent",
        "true",
        ...(kind === "jar"
          ? ["--jarfilter", `^(?:${tops.map(escapeRegex).join("|")})$`]
          : []),
      ];
      if (tops.length > 0)
        await this.#run(profile, args, {
          cwd: root.path,
          signal,
          acceptNonZeroExit: false,
        });
      const decompiled = await collectSources(root.path, chosen, kind);
      const report: JvmArtifact = jvmArtifactSchema.parse({
        artifact: {
          path: input.path,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
          kind,
        },
        classes,
        decompiled,
        tool_profile: {
          decompiler: "CFR",
          release: CFR_RELEASE,
          jar_path: profile.jarPath,
          jar_sha256: profile.jarSha256,
          java_command: profile.java,
          java_version: versions.java,
          arguments:
            tops.length > 0
              ? args.map((value) =>
                  value === snapshot ? `<private copy>.${kind}` : value,
                )
              : [],
          timeout_ms: CFR_LIMITS.timeoutMs,
          output_budget_bytes: CFR_LIMITS.outputBytes,
        },
        runtime_execution: "not-performed",
        limitations: LIMITATIONS,
      });
      result = ok(
        createAnalysisExecution(report, CFR_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      result = err(cfrFailure(cause, phase, input.path));
    }
    return this.#release(root, result);
  }

  async #profile(signal?: AbortSignal): Promise<ToolProfile> {
    const configured = this.environment.REA_CFR_JAR ?? "";
    if (!isAbsolute(configured))
      throw new Error(
        "REA_CFR_JAR must be the absolute path of cfr-0.152.jar.",
      );
    const jarPath = await realpath(configured);
    const jar = await readStableArtifact(jarPath, 64 * 1024 * 1024, signal);
    const javaHome = this.environment.JAVA_HOME;
    const executable = process.platform === "win32" ? "java.exe" : "java";
    let java = executable;
    if (javaHome !== undefined) {
      if (!isAbsolute(javaHome))
        throw new Error(
          "JAVA_HOME must be absolute; omit it to use java on PATH.",
        );
      java = join(javaHome, "bin", executable);
      await access(java, constants.X_OK);
      if (!(await stat(java)).isFile())
        throw new Error(`JAVA_HOME java is not a regular file: ${java}`);
    }
    return { jarPath, jarSha256: jar.sha256, java };
  }

  /** Confirm the Java runtime starts and the jar is exactly CFR 0.152. */
  async #versions(profile: ToolProfile, cwd: string, signal?: AbortSignal) {
    const java = await this.#run(profile, ["-version"], {
      cwd,
      signal,
      acceptNonZeroExit: true,
    });
    const cfr = await this.#run(
      profile,
      ["-jar", profile.jarPath, "--version"],
      {
        cwd,
        signal,
        acceptNonZeroExit: true,
      },
    );
    // CFR prints its banner on stderr.
    const banner = `${cfr.stdout}${cfr.stderr}`.trim();
    if (banner !== `CFR ${CFR_RELEASE}`)
      throw new Error(
        `REA_CFR_JAR reported "${banner}"; expected CFR ${CFR_RELEASE}.`,
      );
    return { java: java.stderr.trim() };
  }

  async #run(
    profile: ToolProfile,
    args: readonly string[],
    run: {
      readonly cwd: string;
      readonly signal: AbortSignal | undefined;
      readonly acceptNonZeroExit: boolean;
    },
  ): Promise<{ readonly stdout: string; readonly stderr: string }> {
    const snapshot = await runOwnedCommand(
      {
        command: profile.java,
        arguments: args,
        cwd: run.cwd,
        runId: `rea-cfr-${randomUUID()}`,
        hostEnvironment: this.environment,
      },
      {
        timeoutMs: CFR_LIMITS.timeoutMs,
        diagnosticBytes: CFR_LIMITS.diagnosticBytes,
        acceptNonZeroExit: run.acceptNonZeroExit,
      },
      {
        ...(run.signal === undefined ? {} : { signal: run.signal }),
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      },
    );
    return {
      stdout: snapshot.stdout.text,
      stderr: withoutJvmEnvironmentNotices(snapshot.stderr.text),
    };
  }

  async #jarInventory(
    input: InspectJvmArtifactInput,
    snapshot: string,
    signal?: AbortSignal,
  ) {
    const jar = await listJarClasses(snapshot, signal);
    try {
      const byName = new Map(jar.classes.map((item) => [item.name, item]));
      const missing = input.classes.filter((name) => !byName.has(name));
      if (missing.length > 0)
        throw new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["classes"],
            reason: "invalid_value",
            message: `The JAR has no class entries for: ${missing.join(", ")}`,
          },
        ]);
      const names = new Set(byName.keys());
      const chosen: SelectedClass[] = [];
      for (const name of new Set(input.classes)) {
        const entry = byName.get(name);
        if (entry === undefined) continue;
        const observed = await jar.read(entry.entry, signal);
        if (observed.header.name !== name)
          throw new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["classes"],
              reason: "invalid_value",
              message: `JAR entry ${entry.entry} declares class ${observed.header.name}, not ${name}.`,
            },
          ]);
        chosen.push({
          name,
          topLevel: topLevelClass(name, names),
          sha256: observed.sha256,
          header: observed.header,
        });
      }
      return { classes: jar.classes, chosen };
    } finally {
      await jar.close();
    }
  }

  async #release(
    root: Runtime | undefined,
    result: Result<AnalysisExecution, AnalysisError>,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (root === undefined) return result;
    try {
      await root.close();
      return result;
    } catch (cause: unknown) {
      this.#pendingRoots.add(root);
      return err(
        new ProviderCleanupError(
          CFR_PROVIDER_IDENTITY.id,
          [root.path],
          {
            reason: cause instanceof Error ? cause.message : String(cause),
            previous_error: result.ok
              ? null
              : projectAnalysisError(result.error),
          },
          { operation: OPERATION, cause },
        ),
      );
    }
  }
}

const artifactKind = (bytes: Buffer): "class" | "jar" => {
  if (isJvmClassFile(bytes)) return "class";
  const zip = bytes.subarray(0, 4).toString("latin1");
  if (zip === "PK\x03\x04" || zip === "PK\x05\x06") return "jar";
  throw new AnalysisInputError(OPERATION, undefined, [
    {
      path: ["path"],
      reason: "invalid_format",
      message: "Expected a JVM class file (0xCAFEBABE) or a JAR (ZIP) archive.",
    },
  ]);
};

/** A standalone class is its own inventory and is always decompiled. */
const classInventory = (
  input: InspectJvmArtifactInput,
  selected: { readonly bytes: Buffer; readonly sha256: string },
) => {
  const header = readJvmClassHeader(selected.bytes);
  const unexpected = input.classes.filter((name) => name !== header.name);
  if (unexpected.length > 0)
    throw new AnalysisInputError(OPERATION, undefined, [
      {
        path: ["classes"],
        reason: "invalid_value",
        message: `This class file declares ${header.name}; it has no class ${unexpected.join(", ")}.`,
      },
    ]);
  return {
    classes: [{ name: header.name, entry: null, bytes: selected.bytes.length }],
    chosen: [
      {
        name: header.name,
        topLevel: header.name,
        sha256: selected.sha256,
        header,
      },
    ],
  };
};

/** Read each top-level source CFR wrote, within the inline output budget. */
const collectSources = async (
  rootPath: string,
  chosen: readonly SelectedClass[],
  kind: "class" | "jar",
) => {
  let total = 0;
  const byTop = new Map<string, SelectedClass[]>();
  for (const item of chosen)
    byTop.set(item.topLevel, [...(byTop.get(item.topLevel) ?? []), item]);
  const sources = [];
  for (const [top, items] of byTop) {
    const relative = `${top.replaceAll(".", "/")}.java`;
    let text: string;
    try {
      text = await readFile(join(rootPath, "out", relative), "utf8");
    } catch (cause: unknown) {
      throw new AnalysisOutputError(
        OPERATION,
        `CFR wrote no source for ${top}${kind === "class" ? " from the class file" : ""}.`,
        { cause },
      );
    }
    total += Buffer.byteLength(text);
    if (total > CFR_LIMITS.outputBytes)
      throw new AnalysisOutputError(
        OPERATION,
        `Decompiled sources exceed the ${String(CFR_LIMITS.outputBytes)}-byte inline budget; select fewer classes.`,
      );
    const [first] = items;
    if (first === undefined) continue;
    sources.push({
      top_level_class: top,
      requested: items.map(({ name }) => name),
      class_sha256: first.sha256,
      class_version: {
        major: first.header.major,
        minor: first.header.minor,
        java_release: javaRelease(first.header.major),
      },
      source_path: relative,
      text,
      sha256: createHash("sha256").update(text).digest("hex"),
      representation: "cfr-decompiled-java",
      cfr_reported_failures: FAILURE_MARKERS.some((marker) =>
        text.includes(marker),
      ),
    });
  }
  return sources;
};

const escapeRegex = (value: string): string =>
  value.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
