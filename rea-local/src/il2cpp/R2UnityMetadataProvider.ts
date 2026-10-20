import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, readFile, realpath } from "node:fs/promises";
import { basename, isAbsolute, join } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { Il2CppMetadataPort } from "../application/il2cpp/Il2CppMetadataPort.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  il2cppMetadataSchema,
  type Il2CppMetadata,
  type InspectIl2CppMetadataInput,
} from "../domain/il2cpp/il2cppMetadata.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { createProviderTargetSnapshot } from "../process/ProviderTargetSnapshot.js";
import { pageClasses, pageEntries } from "./Il2CppMetadataPage.js";
import { r2unityFailure, type R2UnityPhase } from "./R2UnityFailures.js";
import {
  identifySelection,
  type FileIdentity,
  type Selection,
} from "./Il2CppSelection.js";
import {
  parseR2UnityAssemblies,
  parseR2UnityClasses,
  parseR2UnityInterop,
  parseR2UnityStringLiterals,
  R2UnityOutputDrift,
  type R2UnityClassInventory,
} from "./R2UnityOutput.js";
import {
  isSupportedR2UnityVersion,
  R2UNITY_LIMITS,
  R2UNITY_PROVIDER_IDENTITY,
  R2UNITY_VERIFIED_VERSION,
} from "./R2UnityRelease.js";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];
type Runtime = Pick<PrivateRuntimeRoot, "path" | "close">;

const OPERATION = "inspect_il2cpp_metadata";
const LIMITATIONS = [
  "Metadata is decoded by caller-supplied r2unity 1.2, which supports wire versions 24.1 through 35 and 38 through 39 (Unity 2018.3 through Unity 6); encrypted, obfuscated or v24.0 metadata is rejected rather than guessed.",
  "Method addresses come from r2unity's Il2CppCodeRegistration recovery in binary_path: an exported symbol, a caller override, or a section scan. A scan can pair tables wrongly in unusual builds; check addresses against the binary before relying on them.",
  "Names are metadata identifiers, not source: obfuscated builds keep their obfuscated names, and names that are not valid UTF-8 contain U+FFFD.",
  "P/Invoke DLL and entry-point names are not recovered by r2unity 1.2, and reverse-P/Invoke detection needs wire version 29 or later.",
  "Neither file is loaded or executed. r2unity is a trusted caller-supplied program; its SHA-256 and version identify it, not publisher authenticity.",
];

interface ToolProfile {
  readonly path: string;
  readonly sha256: string;
  readonly version: string;
}

/** Parsed listings for one selection, keyed by view. */
interface ViewListing {
  readonly summary: R2UnityClassInventory;
  readonly entries: readonly unknown[];
  readonly arguments: readonly (readonly string[])[];
}

/** Inspect Unity IL2CPP metadata with caller-supplied r2unity 1.2. */
export class R2UnityMetadataProvider implements Il2CppMetadataPort {
  readonly #pendingRoots = new Set<Runtime>();
  #profile: ToolProfile | undefined;
  #cache: { key: string; views: Map<string, ViewListing> } | undefined;

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<Runtime> = () =>
      PrivateRuntimeRoot.create({ prefix: "rea-r2unity-" }),
  ) {}

  /** Drop cached listings and retry retained cleanup. */
  async close(): Promise<void> {
    this.#cache = undefined;
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
        R2UNITY_PROVIDER_IDENTITY.id,
        failures.map(({ path }) => path),
        { failures },
        { operation: OPERATION },
      );
  }

  async inspect(
    input: InspectIl2CppMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    const root: { current?: Runtime } = {};
    let phase: R2UnityPhase = "configuration";
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      await this.#retryPendingCleanup();
      const profile = await this.#toolProfile(signal);
      phase = "artifact";
      const selection = await identifySelection(input, signal);
      phase = "producer";
      const key = [
        profile.sha256,
        selection.metadata.sha256,
        selection.binary?.sha256 ?? "-",
        input.code_registration ?? "-",
      ].join(":");
      if (this.#cache?.key !== key) this.#cache = { key, views: new Map() };
      const views = this.#cache.views;
      const cached = views.get(input.view);
      const listing =
        cached ??
        (await this.#list(input, { profile, selection, root, signal }));
      views.set(input.view, listing);
      const report = buildReport(input, {
        profile,
        selection,
        listing,
        cached: cached !== undefined,
      });
      result = ok(
        createAnalysisExecution(report, R2UNITY_PROVIDER_IDENTITY, {
          subject: {
            path: input.metadata_path,
            format: "file",
            sha256: selection.metadata.sha256,
          },
          locations: [
            { kind: "artifact-path", path: input.metadata_path },
            ...(input.binary_path === undefined
              ? []
              : [{ kind: "artifact-path" as const, path: input.binary_path }]),
          ],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      result = err(r2unityFailure(cause, phase, input.metadata_path));
    }
    return this.#release(root.current, result);
  }

  async #retryPendingCleanup(): Promise<void> {
    const cache = this.#cache;
    await this.close();
    this.#cache = cache;
  }

  /** Resolve REA_R2UNITY_PATH and confirm a supported 1.2 release once per digest. */
  async #toolProfile(signal?: AbortSignal): Promise<ToolProfile> {
    const configured = this.environment.REA_R2UNITY_PATH ?? "";
    if (!isAbsolute(configured))
      throw new Error(
        "REA_R2UNITY_PATH must be the absolute path of the r2unity executable.",
      );
    const path = await realpath(configured);
    await access(path, constants.X_OK);
    const executable = await readStableArtifact(
      path,
      256 * 1024 * 1024,
      signal,
    );
    if (
      this.#profile?.path === path &&
      this.#profile.sha256 === executable.sha256
    )
      return this.#profile;
    const banner = (
      await this.#run(
        { path, sha256: executable.sha256, version: "" },
        ["-v"],
        {
          signal,
        },
      )
    ).trim();
    const version = /^r2unity (\d+\.\d+\.\d+)$/u.exec(banner)?.[1];
    if (version === undefined || !isSupportedR2UnityVersion(version))
      throw new Error(
        `REA_R2UNITY_PATH reported "${banner.slice(0, 120)}"; expected r2unity 1.2.8 or a later 1.2 release.`,
      );
    this.#profile = { path, sha256: executable.sha256, version };
    return this.#profile;
  }

  /** Snapshot the selection and run the r2unity commands one view needs. */
  async #list(
    input: InspectIl2CppMetadataInput,
    {
      profile,
      selection,
      root,
      signal,
    }: {
      readonly profile: ToolProfile;
      readonly selection: Selection;
      readonly root: { current?: Runtime };
      readonly signal: AbortSignal | undefined;
    },
  ): Promise<ViewListing> {
    const runtime = await this.createRuntime();
    root.current = runtime;
    const snapshot = async (identity: FileIdentity) =>
      basename(
        (
          await createProviderTargetSnapshot(
            identity.path,
            runtime.path,
            identity.sha256,
            {
              providerName: "r2unity",
              ...(signal === undefined ? {} : { signal }),
            },
          )
        ).path,
      );
    const metadata = await snapshot(selection.metadata);
    const binary =
      selection.binary === null ? null : await snapshot(selection.binary);
    const override =
      input.code_registration === undefined
        ? []
        : ["-O", `g_CodeRegistration=${input.code_registration}`];
    const placeholders = new Map([
      [metadata, "<metadata_path>"],
      ...(binary === null ? [] : [[binary, "<binary_path>"] as const]),
    ]);
    const commands: string[][] = [];
    const run = async (args: string[]) => {
      commands.push(args.map((value) => placeholders.get(value) ?? value));
      return this.#run(profile, args, { cwd: runtime.path, signal });
    };
    const summary = () => run(["-c", "-j", "-l", "0", metadata]);
    switch (input.view) {
      case "classes": {
        const inventory = parseR2UnityClasses(
          await run(
            binary === null
              ? ["-c", "-j", metadata]
              : ["-c", "-j", "-f", ...override, binary, metadata],
          ),
        );
        return {
          summary: inventory,
          entries: inventory.classes,
          arguments: commands,
        };
      }
      case "string_literals": {
        const inventory = parseR2UnityClasses(await summary());
        const bytes = await readFile(join(runtime.path, metadata));
        const literals = parseR2UnityStringLiterals(
          await run(["-q", "-z", metadata]),
          bytes,
        );
        return { summary: inventory, entries: literals, arguments: commands };
      }
      case "interop": {
        const inventory = parseR2UnityClasses(await summary());
        const interop = parseR2UnityInterop(
          await run(["-P", "-j", "", metadata]),
          await run(["-R", "-j", ...override, binary ?? "", metadata]),
        );
        assertWireVersion(inventory, interop.wireVersion);
        return {
          summary: inventory,
          entries: interop.entries,
          arguments: commands,
        };
      }
      case "assemblies": {
        const inventory = parseR2UnityClasses(await summary());
        const assemblies = parseR2UnityAssemblies(
          await run(["-S", "-j", "", metadata]),
        );
        assertWireVersion(inventory, assemblies.wireVersion);
        return {
          summary: inventory,
          entries: assemblies.entries,
          arguments: commands,
        };
      }
    }
  }

  async #run(
    profile: ToolProfile,
    args: readonly string[],
    run: { readonly cwd?: string; readonly signal: AbortSignal | undefined },
  ): Promise<string> {
    const snapshot = await runOwnedCommand(
      {
        command: profile.path,
        arguments: args,
        ...(run.cwd === undefined ? {} : { cwd: run.cwd }),
        runId: `rea-r2unity-${randomUUID()}`,
        // User radare2 plugins must not change how r2unity reads the binary.
        hostEnvironment: { ...this.environment, R2_NOPLUGINS: "1" },
      },
      {
        timeoutMs: R2UNITY_LIMITS.timeoutMs,
        diagnosticBytes: R2UNITY_LIMITS.outputBytes,
        acceptNonZeroExit: false,
      },
      {
        ...(run.signal === undefined ? {} : { signal: run.signal }),
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      },
    );
    return snapshot.stdout.text;
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
          R2UNITY_PROVIDER_IDENTITY.id,
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

const assertWireVersion = (
  inventory: R2UnityClassInventory,
  wireVersion: number,
): void => {
  if (inventory.wireVersion !== wireVersion)
    throw new R2UnityOutputDrift(
      "r2unity listings reported different metadata wire versions.",
    );
};

const searchable = {
  string_literals: (item: unknown) => [(item as { text: string }).text],
  interop: (item: unknown) => {
    const entry = item as {
      method: string;
      image: string;
      dll: string | null;
      entry: string | null;
    };
    return [entry.method, entry.image, entry.dll, entry.entry];
  },
  assemblies: (item: unknown) => {
    const entry = item as { name: string; image: string };
    return [entry.name, entry.image];
  },
} as const;

/** Page one cached listing into a schema-checked report. */
const buildReport = (
  input: InspectIl2CppMetadataInput,
  {
    profile,
    selection,
    listing,
    cached,
  }: {
    readonly profile: ToolProfile;
    readonly selection: Selection;
    readonly listing: ViewListing;
    readonly cached: boolean;
  },
): Il2CppMetadata => {
  const page =
    input.view === "classes"
      ? pageClasses(
          listing.entries as Il2CppMetadata["classes"],
          input.query,
          input.offset,
          input.limit,
        )
      : pageEntries(listing.entries, {
          query: input.query,
          fields: searchable[input.view],
          offset: input.offset,
          limit: input.limit,
        });
  const serialized = Buffer.byteLength(JSON.stringify(page.entries));
  if (serialized > R2UNITY_LIMITS.pageBytes)
    throw new AnalysisOutputError(
      OPERATION,
      `This page serializes to ${String(serialized)} bytes, over the ${String(R2UNITY_LIMITS.pageBytes)}-byte page budget; lower limit or narrow query.`,
    );
  const { summary } = listing;
  return il2cppMetadataSchema.parse({
    metadata: {
      ...selection.metadata,
      wire_version: summary.wireVersion,
      unity_range: summary.unityRange,
    },
    native_binary: selection.binary,
    counts: summary.counts,
    native:
      input.view === "classes" && selection.binary !== null
        ? summary.native
        : null,
    page: {
      view: input.view,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: page.total,
      returned: page.entries.length,
    },
    classes: input.view === "classes" ? page.entries : [],
    string_literals: input.view === "string_literals" ? page.entries : [],
    interop: input.view === "interop" ? page.entries : [],
    assemblies: input.view === "assemblies" ? page.entries : [],
    tool_profile: {
      tool: "r2unity",
      version: profile.version,
      verified_version: R2UNITY_VERIFIED_VERSION,
      executable_path: profile.path,
      executable_sha256: profile.sha256,
      arguments: listing.arguments,
      timeout_ms: R2UNITY_LIMITS.timeoutMs,
      output_budget_bytes: R2UNITY_LIMITS.outputBytes,
      cached,
    },
    runtime_execution: "not-performed",
    limitations: LIMITATIONS,
  });
};
