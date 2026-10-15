import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
} from "../application/AnalysisProvider.js";
import type { AnalysisOperation } from "../application/AnalysisProvider.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import type { Result } from "../domain/result.js";
import type {
  ExternalMcpConnection,
  ExternalMcpTool,
} from "../externalMcp/ExternalMcpConnection.js";
import {
  chooseBinaryView,
  decodeCallResult,
  findDeepValue,
  findOpenItem,
  findString,
  formatToolList,
  getString,
  normalizeAddress,
  sameFilePath,
  sha256File,
} from "./BinaryNinjaMcpValues.js";
import {
  isAnalysisError,
  parseOperationInput,
  semanticArguments,
  TOOL_ALIASES,
  validateToolArguments,
} from "./BinaryNinjaMcpArguments.js";
import type { ToolRole } from "./BinaryNinjaMcpArguments.js";
import { BinaryNinjaMcpObservations } from "./BinaryNinjaMcpObservation.js";
import { BinaryNinjaOperationRunner } from "./BinaryNinjaOperations.js";

export {
  BINARY_NINJA_LIMITATIONS,
  BINARY_NINJA_OPERATIONS,
  BINARY_NINJA_PROVIDER_IDENTITY,
} from "./BinaryNinjaIdentity.js";
import {
  BINARY_NINJA_LIMITATIONS,
  BINARY_NINJA_OPERATIONS,
  BINARY_NINJA_PROVIDER_IDENTITY,
} from "./BinaryNinjaIdentity.js";

const signalIsAborted = (signal?: AbortSignal): boolean =>
  signal?.aborted === true;

type BinaryNinjaTargetObservation = {
  readonly path: string;
  readonly sha256: string;
  readonly imageBase: string | null;
  readonly binaryView: string;
};

export class BinaryNinjaAnalysisClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #startup: Promise<void> | undefined;
  #closed = false;
  #closePromise: Promise<Result<null, AnalysisError>> | undefined;
  #tools = new Map<string, ExternalMcpTool>();
  #selectedTools = new Map<ToolRole, string>();
  #openItemHandle: string | undefined;
  #binaryViewHandle: string | undefined;
  #itemPath: string | undefined;
  #initialImageBase: string | undefined;
  #observations = new BinaryNinjaMcpObservations();
  #operations = new BinaryNinjaOperationRunner(
    this.#selectedTools,
    (name) => this.#tool(name),
    (name, args, signal) => this.#invoke(name, args, signal),
    () => this.#binaryViewHandle,
  );

  constructor(
    private readonly target: BinaryTarget,
    private readonly connection: ExternalMcpConnection,
    private readonly allowedTools: readonly string[],
    private readonly profile?: AnalysisProfileCommitment,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: { readonly signal?: AbortSignal },
  ) {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options?.signal),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ) {
    if (this.#closed)
      return err(
        new AnalysisProtocolError(
          "Binary Ninja provider session is closed; reopen the target.",
        ),
      );
    if (signalIsAborted(signal))
      return err(new AnalysisCancelledError(operation));
    const parsed = await this.#validateInput(operation, parameters);
    if (!parsed.ok) return parsed;
    try {
      return await this.#performOperation(operation, parsed.value, signal);
    } catch (cause: unknown) {
      return this.#presentFailure(operation, cause, signal);
    }
  }

  async #validateInput(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
  ) {
    if (!(BINARY_NINJA_OPERATIONS as readonly string[]).includes(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          BINARY_NINJA_PROVIDER_IDENTITY.id,
          operation,
          "The official Binary Ninja adapter does not declare this normalized operation; use its caller-configured MCP tools through the generic bridge if desired.",
        ),
      );
    const parsed = parseOperationInput(operation, parameters);
    if (!parsed.ok) return parsed;
    const document = parsed.value.document;
    if (
      typeof document === "string" &&
      !(await sameFilePath(document, this.target.path))
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["document"],
            reason: "invalid_value",
            expected: this.target.path,
            message:
              "Binary Ninja document must be the REA+-bound input; omit document or use the admitted path.",
          },
        ]),
      );
    return parsed;
  }

  async #performOperation(
    operation: AnalysisOperation,
    input: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ) {
    this.#observations.reset();
    await this.#start(signal);
    const before = await this.#observe(signal);
    if (signalIsAborted(signal))
      return err(new AnalysisCancelledError(operation));
    const result = await this.#operations.execute(operation, input, signal);
    if (signalIsAborted(signal))
      return err(new AnalysisCancelledError(operation));
    const after = await this.#observe(signal);
    if (signalIsAborted(signal))
      return err(new AnalysisCancelledError(operation));
    return ok(this.#createExecution(result, before, after));
  }

  #createExecution(
    result: JsonValue,
    before: BinaryNinjaTargetObservation,
    after: BinaryNinjaTargetObservation,
  ) {
    const procedureAddress = this.#operations.lastProcedureAddress;
    return createAnalysisExecution(result, BINARY_NINJA_PROVIDER_IDENTITY, {
      rawResult: {
        server: this.connection.serverInfo(),
        before,
        after,
        ...this.#observations.rawResultFields(),
      },
      limitations: [
        ...BINARY_NINJA_LIMITATIONS,
        ...(this.#observations.omitted
          ? [
              "Raw upstream tool responses exceeded REA+'s 1 MB Evidence cap; normalized results are retained but some raw observations were omitted.",
            ]
          : []),
      ],
      locations: [
        { kind: "artifact-path", path: this.target.path },
        ...(procedureAddress === undefined
          ? []
          : [{ kind: "address" as const, address: procedureAddress }]),
      ],
      subject: {
        path: this.target.path,
        sha256: this.target.sha256,
        format: this.target.format,
        ...(this.target.architecture === undefined
          ? {}
          : { architecture: this.target.architecture }),
      },
      ...(this.profile === undefined ? {} : { analysisProfile: this.profile }),
    });
  }

  #presentFailure(
    operation: AnalysisOperation,
    cause: unknown,
    signal?: AbortSignal,
  ) {
    if (signalIsAborted(signal))
      return err(new AnalysisCancelledError(operation, { cause }));
    if (isAnalysisError(cause)) return err(cause);
    if (cause instanceof z.ZodError)
      return err(
        new AnalysisOutputError(
          operation,
          `Binary Ninja MCP returned malformed or unsupported data: ${cause.issues.map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`).join("; ")}`,
          { cause },
        ),
      );
    return err(
      new ProviderAdapterError(BINARY_NINJA_PROVIDER_IDENTITY.id, operation, {
        cause,
        diagnostics: {
          reason:
            cause instanceof Error ? cause.message : "Unknown upstream failure",
          recovery:
            "Check the caller-supplied official Binary Ninja MCP server, its exact allowedTools list, and the current official tool catalog.",
        },
      }),
    );
  }

  async #start(signal?: AbortSignal): Promise<void> {
    if (this.#startup !== undefined) return this.#startup;
    this.#startup = this.#initialize(signal);
    return this.#startup;
  }

  async #initialize(signal?: AbortSignal): Promise<void> {
    const discovered = await this.connection.connect(signal);
    this.#tools = new Map(discovered.map((tool) => [tool.name, tool]));
    const missingRoles: string[] = [];
    for (const role of Object.keys(TOOL_ALIASES) as ToolRole[]) {
      const selected = TOOL_ALIASES[role].find(
        (name) => this.#tools.has(name) && this.allowedTools.includes(name),
      );
      if (selected === undefined) missingRoles.push(role);
      else this.#selectedTools.set(role, selected);
    }
    if (missingRoles.length > 0)
      throw new AnalysisProtocolError(
        `Configured server does not expose an allowlisted official Binary Ninja MCP contract for: ${missingRoles.join(", ")}. Detected tools: ${formatToolList(discovered.map(({ name }) => name))}. Add the exact read-only tool names to binary-ninja.allowedTools; see docs/external-mcp-bridge.md.`,
      );

    const openListName = this.#selectedTools.get("openItems");
    const openName = this.#selectedTools.get("openItemOpen");
    const viewsName = this.#selectedTools.get("binaryViews");
    const setActiveName = this.#selectedTools.get("setActive");
    const overviewName = this.#selectedTools.get("overview");
    if (
      openListName === undefined ||
      openName === undefined ||
      viewsName === undefined ||
      setActiveName === undefined ||
      overviewName === undefined
    )
      throw new AnalysisProtocolError(
        "Binary Ninja MCP binding tools disappeared.",
      );

    const openList = await this.#invoke(openListName, {}, signal);
    let item = await findOpenItem(openList, this.target.path);
    if (item === undefined) {
      const opened = await this.#invoke(
        openName,
        semanticArguments(openName, this.#tool(openName), {
          path: this.target.path,
        }),
        signal,
      );
      this.#openItemHandle = findString(opened, [
        "openItem",
        "open_item",
        "openItemHandle",
        "open_item_handle",
        "handle",
      ]);
      if (this.#openItemHandle === undefined)
        throw new AnalysisProtocolError(
          "Binary Ninja bn_open_item_open did not return a server-issued openItem handle.",
        );
      const refreshed = await this.#invoke(openListName, {}, signal);
      item = await findOpenItem(
        refreshed,
        this.target.path,
        this.#openItemHandle,
      );
    } else this.#openItemHandle = item.handle;
    if (item === undefined || this.#openItemHandle === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja open-item discovery did not bind a handle to the REA+ input path.",
      );
    if (!(await sameFilePath(item.path, this.target.path)))
      throw new AnalysisProtocolError(
        "Binary Ninja open-item path differs from the admitted REA+ target.",
      );
    this.#itemPath = item.path;

    const viewListTool = this.#tool(viewsName);
    const viewList = await this.#invoke(
      viewsName,
      semanticArguments(viewsName, viewListTool, {
        openItem: this.#openItemHandle,
      }),
      signal,
    );
    const view = chooseBinaryView(viewList);
    if (view === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja did not expose a selectable BinaryView for the bound open item.",
      );
    this.#binaryViewHandle = view.handle;
    await this.#activate(signal);
    const observation = await this.#observe(signal);
    this.#initialImageBase = observation.imageBase ?? undefined;
  }

  async #activate(signal?: AbortSignal): Promise<void> {
    const name = this.#selectedTools.get("setActive");
    if (name === undefined || this.#binaryViewHandle === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja has no bound BinaryView handle.",
      );
    const tool = this.#tool(name);
    await this.#invoke(
      name,
      semanticArguments(name, tool, {
        binaryView: this.#binaryViewHandle,
        openItem: this.#openItemHandle,
      }),
      signal,
    );
  }

  async #observe(signal?: AbortSignal): Promise<BinaryNinjaTargetObservation> {
    if (signalIsAborted(signal))
      throw new AnalysisCancelledError("binary_overview");
    const openItemHandle = this.#openItemHandle;
    const binaryViewHandle = this.#binaryViewHandle;
    const boundPath = this.#itemPath;
    if (
      openItemHandle === undefined ||
      binaryViewHandle === undefined ||
      boundPath === undefined
    )
      throw new AnalysisProtocolError(
        "Binary Ninja session has no target binding.",
      );
    await this.#activate(signal);
    const overviewName = this.#selectedTools.get("overview");
    if (overviewName === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja overview tool is unavailable.",
      );
    const overview = await this.#invoke(
      overviewName,
      semanticArguments(overviewName, this.#tool(overviewName), {
        openItem: openItemHandle,
        binaryView: binaryViewHandle,
      }),
      signal,
    );
    const path =
      getString(overview, [
        "path",
        "filePath",
        "file_path",
        "inputPath",
        "input_path",
      ]) ?? boundPath;
    if (!(await sameFilePath(path, this.target.path)))
      throw new AnalysisProtocolError(
        "The active BinaryView no longer matches the admitted REA+ input path.",
      );
    const digest = await sha256File(path);
    if (digest.toLowerCase() !== this.target.sha256.toLowerCase())
      throw new AnalysisProtocolError(
        "The Binary Ninja input SHA-256 no longer matches the admitted REA+ target.",
      );
    const reportedDigest = getString(overview, [
      "sha256",
      "sha_256",
      "inputSha256",
    ]);
    if (
      reportedDigest !== undefined &&
      reportedDigest.toLowerCase() !== this.target.sha256.toLowerCase()
    )
      throw new AnalysisProtocolError(
        "Binary Ninja's reported input SHA-256 differs from the admitted REA+ target.",
      );
    const imageBaseValue = findDeepValue(overview, [
      "imageBase",
      "image_base",
      "imagebase",
      "baseAddress",
      "base_address",
    ]);
    const imageBase = normalizeAddress(imageBaseValue) ?? null;
    if (
      this.#initialImageBase !== undefined &&
      imageBase !== this.#initialImageBase
    )
      throw new AnalysisProtocolError(
        "Binary Ninja's active-view image base changed or became unavailable during the REA+ session; reopen the target.",
      );
    return {
      path,
      sha256: digest,
      imageBase,
      binaryView: binaryViewHandle,
    };
  }

  async #invoke(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    if (signalIsAborted(signal)) throw new AnalysisCancelledError(name);
    if (!this.allowedTools.includes(name))
      throw new AnalysisCapabilityUnavailableError(
        BINARY_NINJA_PROVIDER_IDENTITY.id,
        name,
        "The official Binary Ninja tool is not in binary-ninja.allowedTools.",
      );
    const tool = this.#tool(name);
    validateToolArguments(tool, args);
    const raw = await this.connection.call(name, args, signal);
    if (signalIsAborted(signal)) throw new AnalysisCancelledError(name);
    const value = decodeCallResult(raw);
    this.#observations.record(name, args, value);
    return value;
  }

  #tool(name: string): ExternalMcpTool {
    const tool = this.#tools.get(name);
    if (tool === undefined)
      throw new AnalysisProtocolError(
        `Binary Ninja MCP tool ${name} is unavailable.`,
      );
    return tool;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = this.#closeOnce();
    this.#closePromise = closing.finally(() => {
      this.#closePromise = undefined;
    });
    return this.#closePromise;
  }

  async #closeOnce(): Promise<Result<null, AnalysisError>> {
    await this.#tail;
    if (this.#closed) return ok(null);
    try {
      // Do not call bn_open_item_close or bn_open_item_save: a GUI handle may
      // refer to an item the user had open before the REA+ session.
      await this.connection.close();
      this.#closed = true;
      return ok(null);
    } catch (cause: unknown) {
      return err(
        new ProviderAdapterError(BINARY_NINJA_PROVIDER_IDENTITY.id, "close", {
          cause,
          diagnostics: {
            reason:
              cause instanceof Error
                ? cause.message
                : "Unknown cleanup failure",
            recovery:
              "The MCP transport did not close cleanly. Do not save or close the user's Binary Ninja item on REA+'s behalf.",
          },
        }),
      );
    }
  }
}
