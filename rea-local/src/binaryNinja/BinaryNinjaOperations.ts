import {
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ExternalMcpTool } from "../externalMcp/ExternalMcpConnection.js";
import { searchAddressedItems } from "../contracts/analysisSearchContract.js";
import { BINARY_NINJA_PROVIDER_IDENTITY } from "./BinaryNinjaIdentity.js";
import {
  assemblyText,
  collectionPage,
  compareAddresses,
  functionText,
  functionRecords,
  normalizeAddress,
  stringRecords,
  MAX_COLLECTION_ITEMS,
  MAX_COLLECTION_PAGES,
  MAX_PAGE_SIZE,
} from "./BinaryNinjaMcpValues.js";
import {
  requiredProcedure,
  semanticArguments,
  validateToolOutput,
} from "./BinaryNinjaMcpArguments.js";
import type { ToolRole } from "./BinaryNinjaMcpArguments.js";
import type { FunctionRecord, StringRecord } from "./BinaryNinjaMcpValues.js";

export class BinaryNinjaOperationRunner {
  #lastProcedureAddress: string | undefined;

  constructor(
    private readonly selectedTools: ReadonlyMap<ToolRole, string>,
    private readonly getTool: (name: string) => ExternalMcpTool,
    private readonly invoke: (
      name: string,
      args: Readonly<Record<string, JsonValue>>,
      signal?: AbortSignal,
    ) => Promise<JsonValue>,
    private readonly getBinaryView: () => string | undefined,
  ) {}

  get lastProcedureAddress(): string | undefined {
    return this.#lastProcedureAddress;
  }

  async execute(
    operation: string,
    input: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    this.#lastProcedureAddress = undefined;
    return this.#run(operation, input, signal);
  }

  async #run(
    operation: string,
    input: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    if (operation === "list_procedures" || operation === "search_procedures") {
      const functions = await this.#listFunctions(signal);
      const items = functions.map(({ address, name }) => ({
        address,
        value: name,
      }));
      return operation === "list_procedures"
        ? items
        : searchAddressedItems(items, input);
    }
    if (operation === "list_strings" || operation === "search_strings") {
      const strings = await this.#listStrings(signal);
      const filtered =
        input.address === undefined
          ? strings
          : strings.filter(
              ({ address }) => address === normalizeAddress(input.address),
            );
      return operation === "search_strings"
        ? searchAddressedItems(filtered, input)
        : filtered;
    }
    if (operation === "procedure_address") {
      const procedure = requiredProcedure(input.procedure);
      const functionRecord = await this.#resolveFunction(procedure, signal);
      return functionRecord.address;
    }
    if (
      operation === "procedure_pseudo_code" ||
      operation === "procedure_assembly"
    ) {
      const fn = await this.#resolveFunction(
        requiredProcedure(input.procedure),
        signal,
      );
      const role =
        operation === "procedure_pseudo_code" ? "decompile" : "disassembly";
      const toolName = this.selectedTools.get(role);
      if (toolName === undefined)
        throw new AnalysisProtocolError(
          `Binary Ninja ${role} tool is unavailable.`,
        );
      const tool = this.getTool(toolName);
      const args = semanticArguments(toolName, tool, {
        function: fn.address,
        binaryView: this.getBinaryView(),
        ...(fn.arch === undefined ? {} : { arch: fn.arch }),
      });
      const value = await this.invoke(toolName, args, signal);
      const text =
        operation === "procedure_pseudo_code"
          ? functionText(value)
          : assemblyText(value);
      return text;
    }
    throw new AnalysisCapabilityUnavailableError(
      BINARY_NINJA_PROVIDER_IDENTITY.id,
      operation,
      "The official Binary Ninja adapter has no normalized route for this operation.",
    );
  }

  async #listFunctions(signal?: AbortSignal): Promise<FunctionRecord[]> {
    const toolName = this.selectedTools.get("functions");
    if (toolName === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja function-list tool is unavailable.",
      );
    const result: FunctionRecord[] = [];
    let offset = 0;
    let expectedTotal: number | undefined;
    let pages = 0;
    while (true) {
      if (pages >= MAX_COLLECTION_PAGES)
        throw new AnalysisProtocolError(
          "Binary Ninja function inventory exceeded REA+'s pagination-page safety cap.",
        );
      pages += 1;
      const tool = this.getTool(toolName);
      const args = semanticArguments(toolName, tool, {
        offset,
        limit: MAX_PAGE_SIZE,
        binaryView: this.getBinaryView(),
      });
      const value = await this.invoke(toolName, args, signal);
      validateToolOutput(tool, value);
      const page = functionRecords(value);
      const pagination = collectionPage(value, offset, page.length);
      if (pagination.total > MAX_COLLECTION_ITEMS)
        throw new AnalysisProtocolError(
          "Binary Ninja function inventory exceeds REA+'s 100,000-item safety cap.",
        );
      if (expectedTotal !== undefined && pagination.total !== expectedTotal)
        throw new AnalysisProtocolError(
          "Binary Ninja function inventory total changed during pagination.",
        );
      expectedTotal = pagination.total;
      if (result.length + page.length > MAX_COLLECTION_ITEMS)
        throw new AnalysisProtocolError(
          "Binary Ninja function inventory exceeds REA+'s 100,000-item safety cap.",
        );
      result.push(...page);
      if (!pagination.truncated) {
        if (result.length !== pagination.total)
          throw new AnalysisProtocolError(
            "Binary Ninja function inventory ended before its reported total was collected.",
          );
        break;
      }
      if (!("offset" in args))
        throw new AnalysisProtocolError(
          "Binary Ninja reported more rows but its input schema does not advertise the documented offset field.",
        );
      if (pagination.nextOffset === null)
        throw new AnalysisProtocolError(
          "Binary Ninja marked a function inventory truncated without a next offset.",
        );
      offset = pagination.nextOffset;
    }
    const unique = new Set<string>();
    for (const fn of result) {
      const key = `${fn.address}:${fn.arch ?? ""}`;
      if (unique.has(key))
        throw new AnalysisProtocolError(
          "Binary Ninja function pagination returned a duplicate address and architecture.",
        );
      unique.add(key);
    }
    return result.sort(
      (left, right) =>
        compareAddresses(left.address, right.address) ||
        left.name.localeCompare(right.name),
    );
  }

  async #listStrings(signal?: AbortSignal): Promise<StringRecord[]> {
    const toolName = this.selectedTools.get("strings");
    if (toolName === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja string-list tool is unavailable.",
      );
    const result: StringRecord[] = [];
    let offset = 0;
    let expectedTotal: number | undefined;
    let pages = 0;
    while (true) {
      if (pages >= MAX_COLLECTION_PAGES)
        throw new AnalysisProtocolError(
          "Binary Ninja string inventory exceeded REA+'s pagination-page safety cap.",
        );
      pages += 1;
      const tool = this.getTool(toolName);
      const args = semanticArguments(toolName, tool, {
        offset,
        limit: MAX_PAGE_SIZE,
        binaryView: this.getBinaryView(),
      });
      const value = await this.invoke(toolName, args, signal);
      validateToolOutput(tool, value);
      const page = stringRecords(value);
      const pagination = collectionPage(value, offset, page.length);
      if (pagination.total > MAX_COLLECTION_ITEMS)
        throw new AnalysisProtocolError(
          "Binary Ninja string inventory exceeds REA+'s 100,000-item safety cap.",
        );
      if (expectedTotal !== undefined && pagination.total !== expectedTotal)
        throw new AnalysisProtocolError(
          "Binary Ninja string inventory total changed during pagination.",
        );
      expectedTotal = pagination.total;
      if (result.length + page.length > MAX_COLLECTION_ITEMS)
        throw new AnalysisProtocolError(
          "Binary Ninja string inventory exceeds REA+'s 100,000-item safety cap.",
        );
      result.push(...page);
      if (!pagination.truncated) {
        if (result.length !== pagination.total)
          throw new AnalysisProtocolError(
            "Binary Ninja string inventory ended before its reported total was collected.",
          );
        break;
      }
      if (!("offset" in args))
        throw new AnalysisProtocolError(
          "Binary Ninja reported more rows but its input schema does not advertise the documented offset field.",
        );
      if (pagination.nextOffset === null)
        throw new AnalysisProtocolError(
          "Binary Ninja marked a string inventory truncated without a next offset.",
        );
      offset = pagination.nextOffset;
    }
    const uniqueAddresses = new Set<string>();
    for (const string of result) {
      if (uniqueAddresses.has(string.address))
        throw new AnalysisProtocolError(
          "Binary Ninja string pagination returned a duplicate address.",
        );
      uniqueAddresses.add(string.address);
    }
    return result.sort((left, right) =>
      compareAddresses(left.address, right.address),
    );
  }

  async #resolveFunction(
    query: string,
    signal?: AbortSignal,
  ): Promise<FunctionRecord> {
    const functions = await this.#listFunctions(signal);
    const nameMatches = functions.filter(({ name }) => name === query);
    const normalizedAddress = normalizeAddress(query);
    const matches =
      nameMatches.length > 0 || normalizedAddress === undefined
        ? nameMatches
        : functions.filter(({ address }) => address === normalizedAddress);
    if (matches.length === 0)
      throw new AnalysisProtocolError(
        `Binary Ninja did not resolve a function for ${query}.`,
      );
    if (matches.length > 1)
      throw new AnalysisProtocolError(
        `Binary Ninja function query ${query} is ambiguous; use the exact start address and architecture.`,
      );
    const result = matches[0];
    if (result === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja omitted a resolved function.",
      );
    this.#lastProcedureAddress = result.address;
    return result;
  }
}
