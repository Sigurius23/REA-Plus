import { z } from "zod";

import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { sameIdaHostPath } from "./IdaWorkspace.js";

const OFFICIAL_TOOLS = Object.freeze([
  "open_database",
  "execute_python",
  "reference",
  "list_databases",
  "save_database",
  "close_database",
]);

/** Read-only compatibility surface consumed by IdaSessionClient and its runner. */
const NORMALIZED_COMPATIBILITY_TOOLS = Object.freeze([
  "get_metadata",
  "list_functions",
  "list_strings",
  "get_function_by_name",
  "get_function_by_address",
  "decompile_function",
  "disassemble_function",
  "get_callers",
  "get_callees",
  "get_xrefs_to",
]);

const MAX_PAGE_SIZE = 1_000;
const MAX_FUNCTIONS = 100_000;
const MAX_STRINGS = 100_000;
const MAX_INSTRUCTIONS = 20_000;
const MAX_RELATIONSHIPS = 50_000;

const record = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

const stringField = (value: unknown, name: string): string | undefined => {
  const field = record(value)?.[name];
  return typeof field === "string" && field.length > 0 ? field : undefined;
};

const parseJsonStringResult = (value: unknown): JsonValue => {
  if (typeof value !== "string") return jsonValueSchema.parse(value);
  try {
    return jsonValueSchema.parse(JSON.parse(value));
  } catch (cause: unknown) {
    throw new AnalysisProtocolError(
      "The official IDA Python adapter returned malformed JSON.",
      { cause },
    );
  }
};

/**
 * Maps Hex-Rays' compact open_database/execute_python MCP surface to the
 * existing normalized IDA operation runner. Only fixed, locally generated
 * IDAPython queries are sent; caller-supplied source code is never forwarded.
 */
export class OfficialIdaMcpConnection implements IdaMcpConnection {
  #instanceId: string | undefined;
  #sessionId: string | undefined;
  #workspacePath: string | undefined;
  #backend: "gui" | "idalib" | undefined;

  constructor(
    private readonly upstream: IdaMcpConnection,
    private readonly config: IdaConfiguration,
  ) {
    if (config.mode !== "headless")
      throw new TypeError(
        "The official IDA normalized provider requires headless mode and a private input copy.",
      );
  }

  async connect(): Promise<readonly string[]> {
    const tools = await this.upstream.connect();
    const missing = OFFICIAL_TOOLS.filter((name) => !tools.includes(name));
    if (missing.length > 0)
      throw new AnalysisProtocolError(
        `Configured MCP server does not match the official Hex-Rays IDA contract. Missing tools: ${missing.join(", ")}. Detected tools: ${formatToolList(tools)}. Expected the official open_database/execute_python/reference/list_databases/save_database/close_database surface; see docs/ida-provider.md.`,
      );
    return NORMALIZED_COMPATIBILITY_TOOLS;
  }

  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    switch (name) {
      case "idb_open":
        return this.#openPrivateDatabase(args);
      case "idb_list":
        return this.#listDatabases();
      case "idb_close":
        return this.#closePrivateDatabase(args);
      case "server_health":
        return this.#serverHealth();
      case "get_metadata":
        return this.#readMetadata();
      case "list_functions":
        return this.#listFunctions(args);
      case "list_strings":
        return this.#listStrings(args);
      case "get_function_by_name":
      case "get_function_by_address":
        return this.#getFunction(name, args);
      case "decompile_function":
        return this.#decompile(args);
      case "disassemble_function":
        return this.#disassemble(args);
      case "get_callers":
        return this.#relationships("callers", args);
      case "get_callees":
        return this.#relationships("callees", args);
      case "get_xrefs_to":
        return this.#xrefsTo(args);
      default:
        throw new AnalysisProtocolError(
          `Unsupported normalized official IDA operation: ${name}`,
        );
    }
  }

  serverInfo(): JsonValue {
    return this.upstream.serverInfo();
  }

  async close(): Promise<void> {
    await this.upstream.close();
  }

  async #openPrivateDatabase(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const path = requiredString(args.input_path, "input_path");
    const opened = await this.upstream.call("open_database", {
      path,
      set_current: false,
    });
    const instanceId = stringField(opened, "instance_id");
    const backend = stringField(opened, "backend");
    if (instanceId === undefined || (backend !== "idalib" && backend !== "gui"))
      throw new AnalysisProtocolError(
        "Official IDA open_database omitted its instance ID or backend; the private worker cannot be safely owned.",
      );
    this.#instanceId = instanceId;
    this.#sessionId = stringField(args, "preferred_session_id") ?? instanceId;
    this.#workspacePath = path;
    this.#backend = backend;
    if (backend !== "idalib")
      throw new AnalysisProtocolError(
        "The official IDA server did not open REA+'s unique private input copy in an idalib worker; refusing to use or close a GUI database.",
      );
    return {
      success: true,
      session: {
        session_id: this.#sessionId,
        input_path: path,
        backend: "worker",
      },
    };
  }

  async #listDatabases(): Promise<JsonValue> {
    const raw = await this.upstream.call("list_databases", {});
    const instances = record(raw)?.instances;
    if (!Array.isArray(instances))
      throw new AnalysisProtocolError(
        "Official IDA list_databases omitted its instances array.",
      );
    const sessions = instances.flatMap((instance) => {
      const item = record(instance);
      if (item === undefined) return [];
      const path = stringField(item, "path");
      const instanceId = stringField(item, "instance_id");
      const backend = stringField(item, "backend");
      if (path === undefined || (backend !== "gui" && backend !== "idalib"))
        return [];
      const isPrivateTarget =
        this.#workspacePath !== undefined &&
        sameIdaHostPath(path, this.#workspacePath);
      const matchesLease =
        isPrivateTarget &&
        backend === "idalib" &&
        (this.#instanceId === undefined || instanceId === this.#instanceId);
      return [
        {
          session_id:
            matchesLease && this.#sessionId !== undefined
              ? this.#sessionId
              : (instanceId ?? ""),
          input_path: path,
          owned: matchesLease,
          backend: backend === "idalib" ? "worker" : "gui",
          is_active: item.status === "current",
        },
      ];
    });
    return { sessions };
  }

  async #closePrivateDatabase(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const sessionId = requiredString(args.database, "database");
    if (
      this.#backend !== "idalib" ||
      this.#instanceId === undefined ||
      this.#sessionId === undefined ||
      sessionId !== this.#sessionId ||
      this.#workspacePath === undefined
    )
      throw new AnalysisProtocolError(
        "Refusing to close an IDA database that is not the private idalib lease opened by this REA+ session.",
      );
    const instanceId = this.#instanceId;
    const closed = await this.upstream.call("close_database", {
      instance_id: instanceId,
    });
    if (record(closed)?.closed !== true)
      throw new AnalysisProtocolError(
        "Official IDA close_database did not confirm release of REA+'s private idalib lease.",
      );
    this.#instanceId = undefined;
    this.#sessionId = undefined;
    this.#backend = undefined;
    return {
      success: true,
      session_id: sessionId,
      saved: false,
      owned: true,
      backend: "worker",
    };
  }

  async #serverHealth(): Promise<JsonValue> {
    const metadata = record(await this.#readMetadata());
    if (metadata === undefined)
      throw new AnalysisProtocolError("IDA metadata was not an object.");
    return {
      status: "ok",
      input_path: metadata.path as string,
      idb_path: null,
      imagebase: metadata.base as string,
      auto_analysis_ready: true,
      module: metadata.module as string,
    };
  }

  async #readMetadata(): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport os\nimport ida_nalt\n\ndef run(db):\n    path = os.path.realpath(ida_nalt.get_input_file_path())\n    digest = ida_nalt.retrieve_input_file_sha256()\n    return json.dumps({"path": path, "module": os.path.basename(path), "sha256": bytes(digest).hex() if digest else "", "base": hex(int(ida_nalt.get_imagebase()))}, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #listFunctions(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const page = await this.#runPython(
      `import json\nimport idautils\nimport ida_funcs\nimport idc\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    offset = int(args.get("offset", 0))\n    count = min(max(int(args.get("count", 100)), 1), ${MAX_PAGE_SIZE})\n    functions = []\n    for ea in idautils.Functions():\n        function = ida_funcs.get_func(ea)\n        if function is None or int(function.start_ea) != int(ea):\n            continue\n        start = int(function.start_ea)\n        end = int(function.end_ea)\n        functions.append({"address": hex(start), "name": idc.get_func_name(start) or idc.get_name(start) or hex(start), "size": hex(max(0, end - start))})\n        if len(functions) > ${MAX_FUNCTIONS}:\n            raise RuntimeError("function inventory exceeds the REA+ safety cap")\n    functions.sort(key=lambda item: int(item["address"], 16))\n    data = functions[offset:offset + count]\n    next_offset = offset + len(data) if offset + len(data) < len(functions) else None\n    return json.dumps({"data": data, "next_offset": next_offset}, separators=(",", ":"), ensure_ascii=False)`,
    );
    return page;
  }

  async #listStrings(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport idautils\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    offset = int(args.get("offset", 0))\n    count = min(max(int(args.get("count", 100)), 1), ${MAX_PAGE_SIZE})\n    strings = []\n    for item in idautils.Strings():\n        value = str(item)\n        strings.append({"address": hex(int(item.ea)), "string": value, "length": int(getattr(item, "length", len(value)))})\n        if len(strings) > ${MAX_STRINGS}:\n            raise RuntimeError("string inventory exceeds the REA+ safety cap")\n    strings.sort(key=lambda item: int(item["address"], 16))\n    data = strings[offset:offset + count]\n    next_offset = offset + len(data) if offset + len(data) < len(strings) else None\n    return json.dumps({"data": data, "next_offset": next_offset}, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #getFunction(
    name: "get_function_by_name" | "get_function_by_address",
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const key = name === "get_function_by_name" ? "name" : "address";
    return this.#runPython(
      `import json\nimport ida_funcs\nimport idc\n\ndef function_record(ea):\n    function = ida_funcs.get_func(int(ea))\n    if function is None:\n        return None\n    start = int(function.start_ea)\n    end = int(function.end_ea)\n    return {"address": hex(start), "name": idc.get_func_name(start) or idc.get_name(start) or hex(start), "size": hex(max(0, end - start))}\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    query = str(args.get(${pythonStringLiteral(key)}, ""))\n    if ${pythonStringLiteral(name)} == "get_function_by_address":\n        ea = int(query, 0)\n    else:\n        ea = int(idc.get_name_ea_simple(query))\n    result = function_record(ea)\n    if result is None:\n        raise ValueError("IDA could not resolve the requested function")\n    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #decompile(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport ida_funcs\nimport idc\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    function = ida_funcs.get_func(int(str(args["address"]), 0))\n    if function is None:\n        raise ValueError("IDA function is unavailable")\n    result = idc.decompile(int(function.start_ea))\n    return json.dumps(None if result is None else str(result), separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #disassemble(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport ida_funcs\nimport ida_ua\nimport idautils\nimport idc\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    function = ida_funcs.get_func(int(str(args["start_address"]), 0))\n    if function is None:\n        raise ValueError("IDA function is unavailable")\n    start = int(function.start_ea)\n    end = int(function.end_ea)\n    lines = []\n    for ea in idautils.Heads(start, end):\n        if not idc.is_code(idc.get_full_flags(ea)):\n            continue\n        instruction = idc.generate_disasm_line(ea, 0)\n        if instruction is None:\n            raise RuntimeError("IDA omitted a disassembly line")\n        lines.append({"address": hex(int(ea)), "instruction": str(instruction)})\n        if len(lines) > ${MAX_INSTRUCTIONS}:\n            raise RuntimeError("function disassembly exceeds the REA+ safety cap; no partial result was returned")\n    result = {"name": idc.get_func_name(start) or idc.get_name(start) or hex(start), "start_ea": hex(start), "lines": lines, "return_type": None, "arguments": None}\n    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #relationships(
    direction: "callers" | "callees",
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport ida_funcs\nimport ida_idp\nimport ida_ua\nimport idautils\nimport idc\n\ndef function_record(ea):\n    function = ida_funcs.get_func(int(ea))\n    if function is None:\n        return None\n    start = int(function.start_ea)\n    end = int(function.end_ea)\n    return {"address": hex(start), "name": idc.get_func_name(start) or idc.get_name(start) or hex(start), "size": hex(max(0, end - start))}\n\ndef is_call(ea):\n    instruction = ida_ua.insn_t()\n    return ida_ua.decode_insn(instruction, int(ea)) > 0 and ida_idp.is_call_insn(instruction)\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    function = ida_funcs.get_func(int(str(args["function_address"]), 0))\n    if function is None:\n        raise ValueError("IDA function is unavailable")\n    entry = int(function.start_ea)\n    found = {}\n    if ${pythonStringLiteral(direction)} == "callers":\n        sites = idautils.CodeRefsTo(entry, False)\n        for site in sites:\n            if not is_call(site):\n                continue\n            caller = function_record(site)\n            if caller is not None:\n                found[caller["address"]] = caller\n    else:\n        for site in idautils.FuncItems(entry):\n            if not is_call(site):\n                continue\n            for destination in idautils.CodeRefsFrom(site, False):\n                callee = function_record(destination)\n                if callee is not None:\n                    found[callee["address"]] = callee\n            if len(found) > ${MAX_RELATIONSHIPS}:\n                raise RuntimeError("function relationship inventory exceeds the REA+ safety cap")\n    result = sorted(found.values(), key=lambda item: int(item["address"], 16))\n    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #xrefsTo(
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    return this.#runPython(
      `import json\nimport ida_funcs\nimport ida_xref\nimport idautils\nimport idc\n\ndef function_record(ea):\n    function = ida_funcs.get_func(int(ea))\n    if function is None:\n        return None\n    start = int(function.start_ea)\n    end = int(function.end_ea)\n    return {"address": hex(start), "name": idc.get_func_name(start) or idc.get_name(start) or hex(start), "size": hex(max(0, end - start))}\n\ndef run(db):\n    args = json.loads(${pythonJsonLiteral(args)})\n    target = int(str(args["address"]), 0)\n    result = []\n    for xref in idautils.XrefsTo(target, 0):\n        result.append({"address": hex(int(xref.frm)), "type": "code" if ida_xref.iscode(xref.type) else "data", "function": function_record(xref.frm)})\n        if len(result) > ${MAX_RELATIONSHIPS}:\n            raise RuntimeError("cross-reference inventory exceeds the REA+ safety cap")\n    result.sort(key=lambda item: int(item["address"], 16))\n    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)`,
    );
  }

  async #runPython(source: string): Promise<JsonValue> {
    const instanceId = this.#instanceId;
    if (instanceId === undefined)
      throw new AnalysisProtocolError(
        "The official IDA provider has no verified private database instance.",
      );
    const raw = await this.upstream.call("execute_python", {
      code: source,
      instance_id: instanceId,
      timeout: Math.max(0.001, this.config.timeoutMs / 1000),
    });
    const response = record(raw);
    if (response === undefined || !("result" in response))
      return parseJsonStringResult(raw);
    const stderr = response.stderr;
    if (typeof stderr === "string" && stderr.trim().length > 0)
      throw new AnalysisProtocolError(
        `Official IDA Python query reported stderr: ${stderr.slice(0, 2_000)}`,
      );
    return parseJsonStringResult(response.result);
  }
}

const requiredString = (value: unknown, name: string): string => {
  const parsed = z.string().min(1).safeParse(value);
  if (!parsed.success)
    throw new AnalysisProtocolError(
      `Official IDA adapter received an invalid ${name}.`,
    );
  return parsed.data;
};

const pythonJsonLiteral = (value: unknown): string =>
  JSON.stringify(JSON.stringify(value));

const pythonStringLiteral = (value: string): string => JSON.stringify(value);

const formatToolList = (tools: readonly string[]): string =>
  tools.length === 0 ? "<empty>" : tools.slice(0, 64).join(", ");
