# radare2 provider

REA+ includes a normalized deep-analysis provider for a caller-supplied
[radare2](https://github.com/radareorg/radare2) executable. Select it as
`radare2`. REA+ does not install, bundle or update radare2, and the generic
[external MCP bridge](external-mcp-bridge.md) remains available for
`radare2-mcp` tools this provider does not normalize.

## Configure radare2

Install radare2 6.x yourself (REA+ is verified with 6.2.4) and point REA+ at
the executable:

```bash
export REA_RADARE2_PATH=/absolute/path/to/radare2   # or .../r2
export REA_ANALYSIS_PROVIDER=radare2
rea analyze /absolute/path/to/program --json
rea function /absolute/path/to/program main --json
rea decompile /absolute/path/to/program main --json
rea xrefs /absolute/path/to/program 0x401000 --json
```

| Setting                           | Default  | Meaning                                                                        |
| --------------------------------- | -------- | ------------------------------------------------------------------------------ |
| `REA_RADARE2_PATH`                | unset    | Absolute radare2 executable; unset leaves the provider unconfigured            |
| `REA_RADARE2_ANALYSIS`            | `aaa`    | Analysis command run once per session: `aa`, `aaa` or `aaaa`                   |
| `REA_RADARE2_ANALYSIS_TIMEOUT_MS` | `600000` | Deadline for copying the target, starting radare2 and completing that analysis |

Discovery only checks that `REA_RADARE2_PATH` is an executable file. Resolving
an analysis profile runs `radare2 -v` once; releases outside `>=6.0.0 <7.0.0`
are rejected before any analysis session. The profile commits the engine
version and commit, the analysis level and the fixed process arguments, so
cached Evidence never mixes results from different engines or levels. Leaving
`REA_RADARE2_PATH` unset keeps radare2 out of automatic provider selection.

## How a session runs

For each opened target, REA+:

1. Copies the admitted file into a private runtime directory and verifies the
   copy against the target's SHA-256. radare2 never opens the original path.
2. Starts radare2 there in its documented `-q0` pipe mode with `-N` (no user
   rc files or scripts), plain-text output, `cfg.sandbox.grain=all` and
   `cfg.sandbox=true`, which block command execution, sockets and file
   access outside the private directory.
3. Checks that `?V` still reports the profile's engine version and that `ij`
   reports the private copy and its size, then runs the selected analysis.

REA+ never forwards caller text into a radare2 command. Procedure names are
resolved against parsed inventories, and only REA+-formatted `0x` addresses
reach the command line. Inventories are read once per session because REA+
issues no mutating command. Cancelling or timing out an in-flight command
stops that radare2 process; the next operation starts a fresh one and repeats
the analysis. Closing the session stops the process group and removes the
private directory; failed cleanup is retained and reported.

## Normalized operations

| Operation                                        | radare2 source                                        |
| ------------------------------------------------ | ----------------------------------------------------- |
| `list_procedures`, `search_procedures`           | `aflj`                                                |
| `procedure_address`                              | `aflj`, then `isj` symbol names, then `afij`/`afbj`   |
| `procedure_assembly`, `procedure_pseudo_code`    | `pdf`, built-in `pdc`                                 |
| `procedure_callers`, `procedure_callees`         | `axtj` / `axffj` call and cross-function jump edges   |
| `procedure_info`, `resolve_containing_procedure` | `afij`, `afbj`, `afvj`                                |
| `analyze_function` (function dossier)            | `pdfj`, `pdc`, `afbj`, `afvj`, `axtj`, `axffj`, `izj` |
| `list_strings`, `search_strings`                 | `izj` data-section strings                            |
| `list_names`, `address_name`                     | `isj` symbols, function names and `fd.j` flags        |
| `xrefs`                                          | `axtj`                                                |
| `list_segments`                                  | `iSj` sections, or `iSSj` segments without sections   |
| `read_bytes`, `address_to_file_offset`           | `omj` file-backed maps and `p8`                       |
| `list_documents`                                 | The admitted target's file name                       |

Higher-level workflows built on these operations, such as `binary_overview`,
`get_call_graph`, `find_xrefs_to_name` and `batch_decompile`, work unchanged.

Semantics to keep in mind:

- Procedure names keep radare2's flag prefixes (`sym.`, `sym.imp.`, `fcn.`,
  `entry0`). Procedure arguments also accept an exact symbol name such as
  `check_key`, or a `0x` address at or inside a function.
- `procedure_pseudo_code` is radare2's built-in `pdc` output: an annotated,
  low-level listing, not structured decompilation. Use `procedure_assembly`
  when instruction precision matters.
- `read_bytes` returns only bytes whose top-most radare2 IO map is the
  admitted file. radare2 itself reads `0xff` for unmapped addresses and
  zero-fills uninitialized segments such as `.bss`; REA+ reports those ranges
  as incomplete instead of returning those placeholder bytes.
  `address_to_file_offset` also compares a 16-byte probe from radare2 with
  the private copy's bytes.
- Callers and callees include direct calls and jumps to another function's
  entry. Indirect calls radare2 did not resolve are absent, not disproven.
- `list_segments` reports exclusive ends, permissions from the section header,
  and `radare2-section` or `radare2-segment` provenance.
- The function dossier reports callers, callees, block successors, referenced
  strings and names, and indirect calls radare2 left unresolved (for example
  `call rdx`). Reference edges keep radare2's coarse type (`CALL`, `CODE`,
  `DATA`, `STRN`) in an unavailable `kind`, because radare2 does not report
  operand index or read/write access. Outgoing references are limited to
  targets inside loaded sections, since radare2 also records numeric
  immediates as `DATA` references. Comments, native API boundaries and value
  flow are not reported.

## Supported targets

ELF (including MIPS), PE, Mach-O and DOS MZ executables are admitted. These
are refused with a typed reason:

- Archives, databases and non-executable artifacts.
- PE files classified as non-executable.
- Managed (.NET) PE images: radare2 sees only their native stub. Use the
  [managed-code tools](managed-code-analysis.md).
- Universal Mach-O files with several slices: extract the slice first.
- DOS COM images: use Ghidra's COM profile.

## Verification boundary

`tests/boundary/providers/radare2/radare2Provider.real.test.ts` runs the full
provider against a real radare2 when `REA_VERIFY_RADARE2_PATH` is set; otherwise it
is a named skip. Its fixture is a generated x86-64 ELF with a known call
chain, string reference and `.bss` range, so no binary is committed. It was
verified with radare2 6.2.4 built from source on Linux x86-64. Process
lifecycle (cancellation, deadline, crash recovery, version drift) is covered
by a fake radare2 that replays recorded 6.2.4 replies and rejects unmodeled
commands.

Other radare2 6.x releases, other hosts (macOS, Windows), other formats and
architectures, and radare2 decompiler plugins (r2ghidra, r2dec) are not
verified by these lanes.
