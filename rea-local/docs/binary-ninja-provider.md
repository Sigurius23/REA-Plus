# Binary Ninja provider

REA+ provides a dedicated normalized adapter for the caller-supplied official [Binary Ninja MCP server](https://docs.binary.ninja/guide/mcp.html). The adapter is selected as `binary-ninja`; it does not replace generic MCP passthrough, and it does not install or bundle Binary Ninja or upstream MCP code.

## Configure the official server

Add a `binary-ninja` registration to the existing `REA_EXTERNAL_MCP_CONFIG` file. Keep the exact tools needed by your installed server in `allowedTools`; REA+ uses that explicit list as the authority boundary. The official tool catalog can vary across Binary Ninja versions, so inspect the tool list exposed by your installation and use the exact names it reports.

For the GUI server, configure its loopback Streamable HTTP endpoint. Binary Ninja's documented default is `http://127.0.0.1:24642/mcp`; enable and start the MCP server in Binary Ninja first. If you configured a bearer token, keep it in the registration's `headers` and outside version control:

```json
{
  "mcpServers": {
    "binary-ninja": {
      "type": "http",
      "url": "http://127.0.0.1:24642/mcp",
      "headers": {
        "Authorization": "Bearer <your-local-token>"
      },
      "timeoutMs": 300000,
      "allowedTools": [
        "bn_open_item_list",
        "bn_open_item_open",
        "bn_binary_view_list",
        "bn_binary_view_set_active",
        "bn_binary_overview",
        "bn_function_list",
        "bn_string_list",
        "bn_function_decompile",
        "bn_function_disassembly"
      ]
    }
  }
}
```

Omit `headers` when authorization is disabled. If your installed version uses a different official overview, strings, or disassembly tool name, allowlist that exact name only when REA+'s compatibility check reports it as a supported alias. The normalized adapter requires open-item listing/open, BinaryView listing/selection, an overview tool, function and string listing, decompilation, and disassembly. It reports the exact discovered tool names if a required role is unavailable.

For headless stdio, use the caller-installed `binaryninja_mcp` executable where that server is available:

```json
{
  "mcpServers": {
    "binary-ninja": {
      "type": "stdio",
      "command": "/absolute/path/to/binaryninja_mcp",
      "args": [],
      "timeoutMs": 300000,
      "allowedTools": [
        "bn_open_item_list",
        "bn_open_item_open",
        "bn_binary_view_list",
        "bn_binary_view_set_active",
        "bn_binary_overview",
        "bn_function_list",
        "bn_string_list",
        "bn_function_decompile",
        "bn_function_disassembly"
      ]
    }
  }
}
```

Check Binary Ninja's [current platform and edition notes](https://docs.binary.ninja/guide/mcp.html#headless-server): its GUI MCP server is HTTP-only, while the headless stdio server is not included in Free/Personal or native Windows packages at the time of those docs. On native Windows, use the GUI HTTP server. REA+ does not change Binary Ninja MCP settings or start the GUI server during discovery.

## Use the normalized provider

```bash
export REA_EXTERNAL_MCP_CONFIG=/absolute/path/to/external-mcp.json
export REA_ANALYSIS_PROVIDER=binary-ninja
rea function /absolute/path/to/program main --json
rea decompile /absolute/path/to/program main --json
```

The normalized operations are `list_procedures`, `search_procedures`, `list_strings`, `search_strings`, `procedure_address`, `procedure_pseudo_code`, and `procedure_assembly`. Function and string inventory normalization requires the discovered MCP tool to advertise an output schema matching the supported row shape; REA+ does not guess field names when that schema is absent or incompatible. The adapter validates each response against that schema, then checks the documented `count`, `total`, `nextOffset`, and `truncated` metadata, exact offset progression, stable totals, duplicate identities, and 100,000-item/2,048-page safety caps. It uses `offset` and `limit` only when those exact fields are advertised by the input schema. A truncated response without a valid advertised offset is rejected rather than reported as complete. If a tool omits an output schema or changes shape, use the generic MCP bridge to inspect its raw upstream result. Search is performed locally only after complete inventories are validated, using REA+'s literal or ECMAScript Unicode regex semantics. Results become the same normalized REA+ Evidence operations used by other supported providers. `provider.version` identifies the REA+ adapter, not the Binary Ninja engine or server release. Provider cache policy is live.

Only executable inputs are admitted by this normalized route. REA+ and the configured Binary Ninja server must be able to refer to the same local input path and read its bytes. REA+ binds the server-issued open-item and BinaryView handles returned by MCP, checks that the selected item maps to the admitted path, verifies the local SHA-256 around each operation, and rechecks the image base when the installed overview tool exposes one. Binary Ninja's tools operate mostly on its active BinaryView; the GUI server shares that selection with the UI. REA+ may call `bn_binary_view_set_active` to select the bound view, which can change the visible/current selection.

The normalized adapter does not invoke save, close, rename, comment, analysis-update, or mutation tools. Closing the REA+ MCP connection closes its caller-supplied MCP transport; REA+ deliberately does not call `bn_open_item_save` or `bn_open_item_close`, since an item may already belong to the user. A GUI item can remain open after the REA+ session ends. The adapter does not create a private copy of the input file; do not infer that its in-memory Binary Ninja analysis state has been persisted or that a particular `.bndb` revision was opened unless upstream reports it.

The provider does not normalize callers/callees, xrefs, IL, CFG, symbols, imports, exports, memory reads, analysis control, or edits yet. Use the generic external MCP bridge for additional caller-allowlisted tools, with its upstream authority and effects reviewed separately. The generic bridge remains available even when the normalized provider rejects a changed tool schema.

## Verification boundary

REA+'s source tests use a recording MCP connection to verify handle binding, normalized outputs, pagination/error handling, and that save/close tools are not called. They do not prove compatibility with every Binary Ninja edition, release, OS, architecture, or real MCP server. Verify the installed official tool catalog and a real target before relying on a workflow. Follow the [official MCP guide](https://docs.binary.ninja/guide/mcp.html) for platform-specific registration and server lifecycle.
