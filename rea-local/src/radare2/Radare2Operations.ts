import { searchAddressedItems } from "../contracts/analysisSearchContract.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  RADARE2_PROVIDER_IDENTITY,
  type Radare2Operation,
} from "./Radare2Identity.js";
import {
  entryAddress,
  functionBody,
  Radare2Inventory,
  requiredAddress,
  type Radare2Binding,
  type Radare2CommandPort,
} from "./Radare2Inventory.js";
import { analyzeRadare2Function } from "./Radare2FunctionDossier.js";
import { procedureLocals } from "./Radare2Locals.js";
import { mapRadare2FileOffset, readRadare2Bytes } from "./Radare2Memory.js";
import {
  compareRadare2Addresses,
  formatRadare2Address,
  parseRadare2Permissions,
  radare2FlagsAtSchema,
  radare2Reply,
  RADARE2_INVALID_ADDRESS,
} from "./Radare2Values.js";

/** Normalized result plus the radare2 commands that produced it. */
export interface Radare2OperationOutcome {
  readonly result: JsonValue;
  readonly address: string | undefined;
  readonly commands: readonly string[];
}

type Outcome = { readonly result: JsonValue; readonly address?: string };
type Input = Readonly<Record<string, JsonValue>>;

/**
 * Translate REA+ operations into fixed radare2 commands. Caller text is never
 * interpolated: names are resolved against parsed inventories and only
 * REA+-formatted hexadecimal addresses reach the command line.
 */
export class Radare2OperationRunner {
  readonly #inventory: Radare2Inventory;

  constructor(port: Radare2CommandPort, binding: Radare2Binding) {
    this.#inventory = new Radare2Inventory(port, binding);
  }

  async execute(
    operation: Radare2Operation,
    input: Input,
    signal?: AbortSignal,
  ): Promise<Radare2OperationOutcome> {
    this.#inventory.beginOperation();
    this.#requireDocument(operation, input.document);
    const { result, address } = await this.#run(operation, input, signal);
    return { result, address, commands: this.#inventory.commands() };
  }

  async #run(
    operation: Radare2Operation,
    input: Input,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const inventory = this.#inventory;
    switch (operation) {
      case "list_documents":
        return { result: [inventory.binding.documentName] };
      case "list_procedures":
        return { result: await this.#procedureItems(operation, signal) };
      case "search_procedures":
        return {
          result: searchAddressedItems(
            await this.#procedureItems(operation, signal),
            input,
          ),
        };
      case "procedure_address": {
        const fn = await inventory.procedure(
          operation,
          input.procedure,
          signal,
        );
        return { result: entryAddress(fn), address: entryAddress(fn) };
      }
      case "procedure_assembly":
      case "procedure_pseudo_code":
        return this.#procedureText(operation, input.procedure, signal);
      case "procedure_callers":
      case "procedure_callees":
        return this.#procedureCalls(operation, input.procedure, signal);
      case "procedure_info":
        return this.#procedureInfo(operation, input.procedure, signal);
      case "analyze_function": {
        const fn = await inventory.procedure(
          operation,
          input.procedure,
          signal,
        );
        return {
          result: await analyzeRadare2Function(
            inventory,
            operation,
            entryAddress(fn),
            signal,
          ),
          address: entryAddress(fn),
        };
      }
      case "resolve_containing_procedure":
        return this.#containingProcedure(operation, input.address, signal);
      case "list_strings":
      case "search_strings":
        return this.#strings(operation, input, signal);
      case "list_names":
        return this.#names(operation, input.address, signal);
      case "address_name":
        return this.#addressName(operation, input.address, signal);
      case "xrefs":
        return this.#xrefs(operation, input.address, signal);
      case "list_segments":
        return { result: await this.#segments(operation, signal) };
      case "read_bytes":
        return readRadare2Bytes(inventory, operation, input, signal);
      case "address_to_file_offset":
        return mapRadare2FileOffset(
          inventory,
          operation,
          input.address,
          signal,
        );
    }
  }

  #requireDocument(operation: string, document: JsonValue | undefined): void {
    const expected = this.#inventory.binding.documentName;
    if (document === undefined || document === expected) return;
    throw new AnalysisInputError(operation, undefined, [
      {
        path: ["document"],
        reason: "invalid_value",
        expected,
        message:
          "radare2 sessions contain exactly the admitted target; omit document or pass its name.",
      },
    ]);
  }

  async #procedureItems(operation: string, signal?: AbortSignal) {
    return (await this.#inventory.functions(operation, signal)).map((fn) => ({
      address: entryAddress(fn),
      value: fn.name,
    }));
  }

  async #procedureText(
    operation: "procedure_assembly" | "procedure_pseudo_code",
    procedure: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const command =
      operation === "procedure_assembly"
        ? "pdf"
        : this.#inventory.binding.dialect.pseudoCodeCommand;
    if (command === null)
      throw new AnalysisCapabilityUnavailableError(
        RADARE2_PROVIDER_IDENTITY.id,
        operation,
        "Rizin has no built-in pseudo-code command (radare2's pdc); use procedure_assembly.",
      );
    const fn = await this.#inventory.procedure(operation, procedure, signal);
    const text = await this.#inventory.command(
      `${command} @ ${entryAddress(fn)}`,
      signal,
    );
    if (text.trim().length > 0)
      return { result: text, address: entryAddress(fn) };
    if (operation === "procedure_pseudo_code")
      return { result: null, address: entryAddress(fn) };
    throw new AnalysisOutputError(
      operation,
      `radare2 pdf returned no listing for ${fn.name}`,
    );
  }

  async #procedureCalls(
    operation: "procedure_callers" | "procedure_callees",
    procedure: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const inventory = this.#inventory;
    const fn = await inventory.procedure(operation, procedure, signal);
    const at = entryAddress(fn);
    const related = new Set<bigint>();
    if (operation === "procedure_callers") {
      const references = await inventory.referencesToWithFunctions(
        operation,
        fn.addr,
        signal,
      );
      for (const { fcn_addr: caller, type } of references) {
        if (caller === undefined) continue;
        // A jump to the entry from inside the same body is a loop, not a caller.
        if (type === "CALL" || (type === "CODE" && caller !== fn.addr))
          related.add(caller);
      }
    } else {
      const entries = new Set(
        (await inventory.functions(operation, signal)).map(({ addr }) => addr),
      );
      const references = await inventory.referencesFrom(operation, fn, signal);
      for (const { ref: callee, type } of references) {
        if (!entries.has(callee)) continue;
        if (type === "CALL" || (type === "CODE" && callee !== fn.addr))
          related.add(callee);
      }
    }
    return {
      result: [...related]
        .sort(compareRadare2Addresses)
        .map(formatRadare2Address),
      address: at,
    };
  }

  async #procedureInfo(
    operation: string,
    procedure: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const inventory = this.#inventory;
    const fn = await inventory.procedure(operation, procedure, signal);
    const ranges = await inventory.bodyRanges(operation, fn.addr, signal);
    const locals = await procedureLocals(inventory, operation, fn, signal);
    const body = functionBody({ fn, ranges });
    return {
      result: {
        name: fn.name,
        entrypoint: entryAddress(fn),
        basicblock_count: fn.nbbs,
        length: body.available ? body.total_bytes : fn.size,
        signature: fn.signature ?? null,
        locals,
        classification: null,
        body,
      },
      address: entryAddress(fn),
    };
  }

  async #containingProcedure(
    operation: string,
    value: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const address = requiredAddress(operation, value);
    const query = formatRadare2Address(address);
    const loaded = (await this.#inventory.regions(operation, signal)).some(
      ({ start, end }) => address >= start && address < end,
    );
    const containing = loaded
      ? await this.#inventory.functionContaining(operation, address, signal)
      : undefined;
    if (containing === undefined)
      return {
        result: {
          query_address: query,
          found: false,
          procedure: null,
          reason: loaded ? "not_in_procedure" : "outside_segments",
        },
      };
    return {
      result: {
        query_address: query,
        found: true,
        procedure: {
          address: entryAddress(containing.fn),
          name: containing.fn.name,
          classification: null,
          body: functionBody(containing),
        },
      },
      address: entryAddress(containing.fn),
    };
  }

  async #strings(
    operation: "list_strings" | "search_strings",
    input: Input,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const strings = (await this.#inventory.strings(operation, signal)).map(
      (item) => ({
        address: formatRadare2Address(item.address),
        value: item.value,
      }),
    );
    if (operation === "search_strings")
      return { result: searchAddressedItems(strings, input) };
    if (input.address === undefined) return { result: strings };
    const address = formatRadare2Address(
      requiredAddress(operation, input.address),
    );
    return {
      result: strings.filter((item) => item.address === address),
      address,
    };
  }

  /** Binary symbols joined with analyzed function names, unique per address. */
  async #names(
    operation: string,
    value: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const filter =
      value === undefined ? undefined : requiredAddress(operation, value);
    const unique = new Map<string, { address: bigint; name: string }>();
    const add = (address: bigint, name: string): void => {
      if (name.length === 0 || address === RADARE2_INVALID_ADDRESS) return;
      if (filter === undefined || address === filter)
        unique.set(`${address.toString(16)}\0${name}`, { address, name });
    };
    for (const symbol of await this.#inventory.symbols(operation, signal))
      if (symbol.type !== "FILE" && symbol.type !== "SECTION")
        add(symbol.vaddr, symbol.name);
    for (const fn of await this.#inventory.functions(operation, signal))
      add(fn.addr, fn.name);
    const result = [...unique.values()]
      .sort(
        (left, right) =>
          compareRadare2Addresses(left.address, right.address) ||
          left.name.localeCompare(right.name),
      )
      .map(({ address, name }) => ({
        address: formatRadare2Address(address),
        value: name,
      }));
    return filter === undefined
      ? { result }
      : { result, address: formatRadare2Address(filter) };
  }

  async #addressName(
    operation: string,
    value: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const address = requiredAddress(operation, value);
    const at = formatRadare2Address(address);
    const fn = (await this.#inventory.functions(operation, signal)).find(
      ({ addr }) => addr === address,
    );
    if (fn !== undefined) return { result: fn.name, address: at };
    // A binary symbol outranks radare2's generated str.* and section.* flags.
    const symbol = (await this.#inventory.symbols(operation, signal)).find(
      ({ vaddr, type, name }) =>
        vaddr === address &&
        type !== "FILE" &&
        type !== "SECTION" &&
        name.length > 0,
    );
    if (symbol !== undefined) return { result: symbol.name, address: at };
    const [flag] = radare2Reply(
      operation,
      "fd.j",
      await this.#inventory.command(`fd.j @ ${at}`, signal),
      radare2FlagsAtSchema,
    );
    return { result: flag?.name ?? null, address: at };
  }

  async #xrefs(
    operation: string,
    value: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Outcome> {
    const address = requiredAddress(operation, value);
    const at = formatRadare2Address(address);
    const sources = new Set(
      (await this.#inventory.referencesTo(operation, address, signal)).map(
        ({ from }) => from,
      ),
    );
    return {
      result: [...sources]
        .sort(compareRadare2Addresses)
        .map(formatRadare2Address),
      address: at,
    };
  }

  async #segments(operation: string, signal?: AbortSignal) {
    const imageBase = formatRadare2Address(this.#inventory.binding.baseAddress);
    return (await this.#inventory.regions(operation, signal)).map(
      ({ command, name, start, end, perm }) => {
        const provenance =
          command === "iSj" ? "radare2-section" : "radare2-segment";
        return {
          name,
          start: formatRadare2Address(start),
          end: formatRadare2Address(end),
          ...parseRadare2Permissions(perm),
          permissions: { available: true, source: provenance },
          provenance,
          image_base: imageBase,
          sections: [],
        };
      },
    );
  }
}
