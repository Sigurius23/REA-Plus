# External MCP bridge

REA+ can expose tools from MCP servers that you explicitly configure on the same
machine. This is an optional, namespaced bridge—not a catalog of bundled
servers. REA+ does not install, vendor, or claim to verify upstream MCP projects.

The bridge adds three REA+ tools:

- `list_external_mcp_servers` reads the local registration and starts nothing.
- `inspect_external_mcp_tools` connects to one server and reports its current
  advertised tools, JSON Schemas, upstream annotations, and exact allowlist
  status.
- `call_external_mcp_tool` forwards one allowlisted tool call, validates its
  arguments against that tool's advertised input schema, and records the
  projected response as REA+ Evidence.

## Configure

Set `REA_EXTERNAL_MCP_CONFIG` to an **absolute path** to a strict JSON file
(maximum 64 KiB). Server IDs use lowercase letters, digits, and hyphens, and
must start with a letter. Tool names in `allowedTools` are exact, case-sensitive
upstream names; wildcards are not supported.

A stdio registration:

```json
{
  "mcpServers": {
    "my-analysis-server": {
      "type": "stdio",
      "name": "My analysis server",
      "command": "/absolute/path/to/mcp-server",
      "args": [],
      "timeoutMs": 300000,
      "allowedTools": ["read_only_tool"]
    }
  }
}
```

A Streamable HTTP registration must point to a loopback host only:

```json
{
  "mcpServers": {
    "local-analysis-server": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {},
      "allowedTools": ["read_only_tool"]
    }
  }
}
```

`timeoutMs` is optional (default 300,000 ms; accepted range 1–2,147,483,647).
`name`, `args`, `env`, and HTTP `headers` are optional. Use `env` or `headers`
only for values you intentionally grant the selected server. HTTP URLs may use
`localhost`, `127.0.0.1`, or `::1`; URL credentials, query strings, fragments,
non-loopback hosts, redirects, and other transports are refused. Stdio command
and arguments are passed without a shell. The child receives the MCP SDK's
small allowlisted set of inherited environment variables plus the explicit
`env` entries; other REA+ process environment variables are not inherited.

REA+ does not contact a server until `inspect_external_mcp_tools` or
`call_external_mcp_tool` is invoked. Configuration can launch arbitrary local
commands and tool calls can have arbitrary side effects. Configure only servers
you trust, review the discovered description/schema and side effects, and
allowlist only exact tools you intend to call. Upstream `readOnlyHint`,
`destructiveHint`, and descriptions are claims from that server, not a safety
boundary. REA+ marks generic tool calls as potentially mutating, non-idempotent,
filesystem-writing, process-launching, network-accessing, UI-changing, and
data-discarding.

## Provenance, Evidence, and limits

A successful discovery or call produces a normal REA+ Evidence record with an
external-service authority and an `external-mcp:<server-id>` provider identity.
The call result retains its configured server ID, upstream server metadata,
upstream tool name, `isError` status, structured JSON when within limits, and a
bounded projection of the content blocks. An upstream `isError: true` remains an
observed upstream error in the result; it is not silently converted to a REA+
transport failure.

To reduce accidental credential retention, REA+ records a canonical SHA-256 and
byte length for call arguments rather than persisting those argument values in
Evidence. The upstream response is still untrusted and may echo sensitive input.
Image, audio, and binary resource bytes are reported as metadata, not copied.
The current bridge caps JSON Schemas at 32 KiB each, structured content at
64 KiB, content at 64 blocks, each text block at 16 KiB, and total retained
content text at 128 KiB. Omission/truncation is reported in Evidence. These
limits apply after the MCP client has received the upstream response.

The generic bridge does **not** bind an upstream session to the artifact open in
REA+, translate every upstream tool into a REA+ native-analysis operation, or
certify the server's version/platform/transport compatibility. Where REA+ already
has normalized workflows, use the matching profile for the operations it
supports: native Ghidra, Hopper, and legacy IDA providers, plus the dedicated
`ida-official` and `binary-ninja` profiles. The generic route remains available
when you intentionally need a raw upstream tool. An external Ghidra MCP server
is distinct from REA+'s native Ghidra provider and may have different tools,
versions, side effects, and platform limits.

The generic implementation is covered by local schema, allowlist, projection,
and contract tests. No external MCP server is bundled, configured by default,
or live-tested by those tests. Verify the selected upstream project and its
runtime requirements independently before use.

## Analysis-server integrations from the curated list

The bridge can connect to compatible upstream MCP implementations without
copying their source into REA+. It preserves each upstream tool name and result;
it does not make unlike engines interchangeable or turn their tools into REA+'s
native analysis-provider contract.

Use `inspect_external_mcp_tools` with an empty `allowedTools` list first. Review
the server version, descriptions, schemas, annotations, and side effects; then
add only exact tool names you intend to permit. The upstream tool catalog can
change between versions, so do not treat the names below as a permanent API.

| Upstream project                                                  | Supported route to try                                                                                                                                    | Important boundary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Ghidra MCP](https://github.com/bethington/ghidra-mcp)            | Its documented stdio or Streamable HTTP transport; REA+'s loopback HTTP registration applies to HTTP.                                                     | This is separate from REA+'s native Ghidra provider. Upstream tool sets may include scripting, database changes, emulation, or debugger operations; review each discovered tool before allowlisting.                                                                                                                                                                                                                                                                                                                                                                         |
| [Official Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp) | Generic bridge over stdio or loopback Streamable HTTP when exposed, or normalized profile `ida-official` in headless mode.                                | The official server exposes `open_database`, `execute_python`, `reference`, `list_databases`, `save_database`, and `close_database`. The normalized `ida-official` profile binds a private headless database copy and sends only fixed REA+-generated queries; it does not expose caller-controlled Python, save, or GUI navigation. The generic bridge still forwards explicitly allowlisted raw tools and does not independently bind their target to REA+'s input. Check the [IDA provider guide](ida-provider.md) and official IDA/idalib/Python/licensing requirements. |
| [Binary Ninja MCP](https://docs.binary.ninja/guide/mcp.html)      | Generic bridge, or normalized profile `binary-ninja` over the caller-supplied GUI HTTP or supported headless stdio server.                                | The normalized profile currently supports procedure and string inventory/search, address resolution, pseudocode, and assembly. It binds the session-scoped open-item and BinaryView handles and rechecks input identity. The generic bridge does not bind the upstream view to REA+'s artifact. Tool catalogs can change; inspect the installed catalog and check the [Binary Ninja provider guide](binary-ninja-provider.md) for current limits. GUI MCP is HTTP-only; the documented headless server has edition and platform restrictions.                                |
| [radare2-mcp](https://github.com/radareorg/radare2-mcp)           | Generic bridge over its documented stdio transport (`r2pm -r r2mcp`); HTTP is usable only when exposed as a compatible loopback Streamable HTTP endpoint. | Upstream is a C MCP server for radare2/r2pipe and can optionally expose raw r2 commands or r2js; its optional r2xsql-backed SQL tool supports writes. The upstream project documents a read-only mode, but REA+ treats generic calls as potentially mutating and does not bind that upstream session to the REA+ artifact. Inspect the advertised catalog and allowlist only exact tools you intend to call.                                                                                                                                                                 |

For initial discovery, this configuration intentionally allows no upstream tool
calls:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "type": "stdio",
      "name": "Ghidra MCP",
      "command": "/absolute/path/to/ghidra-mcp-launcher",
      "args": ["--transport", "stdio"],
      "allowedTools": []
    },
    "ida-hexrays": {
      "type": "stdio",
      "name": "Official Hex-Rays IDA MCP",
      "command": "/absolute/path/to/uvx",
      "args": [
        "--from",
        "ida-mcp==PINNED_VERSION",
        "ida-mcp",
        "stdio",
        "--agent=rea"
      ],
      "allowedTools": []
    },
    "binary-ninja-gui": {
      "type": "http",
      "name": "Binary Ninja GUI MCP",
      "url": "http://127.0.0.1:24642/mcp",
      "headers": {},
      "allowedTools": []
    },
    "binary-ninja-headless": {
      "type": "stdio",
      "name": "Binary Ninja headless MCP",
      "command": "/absolute/path/to/binaryninja_mcp",
      "args": [],
      "allowedTools": []
    },
    "radare2-mcp": {
      "type": "stdio",
      "name": "radare2 MCP",
      "command": "/absolute/path/to/r2pm",
      "args": ["-r", "r2mcp"],
      "allowedTools": []
    }
  }
}
```

These are registration shapes, not REA+-verified installations or live
compatibility claims. The radare2-mcp upstream README documents installation via
`r2pm -Uci r2mcp` and stdio launch via `r2pm -r r2mcp`; use an absolute `r2pm`
path in this configuration. Replace each executable, version, endpoint, and
arguments with the upstream's current documented values. For authenticated HTTP,
put the explicit header in `headers` rather than embedding credentials in the
URL. After saving the file, inspect each server and add exact allowlisted tools.
Use REA+'s native Ghidra/IDA/Hopper provider when you need REA+'s normalized
native operations; use the generic bridge when you intentionally want the
upstream tool surface.

### ILSpy and runtime instrumentation

REA+ already supports importing caller-supplied ILSpy reconstruction against
`inspect_managed_members` Evidence through `import_managed_reconstruction`, and
can run an optional `ilspycmd` oracle when `REA_ILSPY_CMD_PATH` is set. Decompiled
C# remains inference, not canonical byte evidence; see the
[managed-code guide](managed-code-analysis.md).

[Frida](https://github.com/frida/frida) and
[Objection](https://github.com/sensepost/objection) are runtime-instrumentation
tools, not MCP servers. REA+ now has a separate optional, caller-configured
provider with Frida device/process inventory, explicitly confirmed caller-script
execution, and explicitly confirmed Objection commands. It is not implemented
through the generic MCP bridge and does not install either upstream tool. See
the [runtime instrumentation guide](mobile-runtime-instrumentation.md) for
configuration, output bounds, Evidence handling, and state-change warnings.
