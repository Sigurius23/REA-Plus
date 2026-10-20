# AOB signatures and Cheat Engine tables

Game modders locate code by array-of-bytes (AOB) signatures: instruction
bytes with wildcards over the parts that change between builds. Two tools
work with them offline. Neither attaches to a process or runs a script.

- `scan_byte_patterns` / `scan-byte-patterns` scans a PE, ELF, Mach-O or raw
  file for signatures and maps every match to its section, address and RVA.
- `inspect_cheat_table` / `inspect-cheat-table` reads a Cheat Engine table
  (`.CT`). With the module of a new game build, it re-scans the table's
  signatures and checks its `assert` bytes, showing which cheats survived the
  update.

```sh
rea scan-byte-patterns /games/Example/GameAssembly.dll \
  --pattern "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40" --json
rea inspect-cheat-table /tables/Example.CT --binary_path /games/Example/GameAssembly.dll --json
```

```json
{
  "name": "scan_byte_patterns",
  "arguments": {
    "path": "/games/Example/GameAssembly.dll",
    "patterns": [
      {
        "name": "GameManager.instance",
        "pattern": "48 8B 05 ?? ?? ?? ?? 48 85 C0"
      }
    ]
  }
}
```

## Pattern syntax

Cheat Engine and IDA forms are both accepted: space-separated hex bytes with
`??` or `?` for any byte, nibble wildcards such as `4?` or `?F`, or an unspaced
string like `488B05????????`. A pattern is 1 to 256 bytes with at least one
fully fixed byte.

## scan_byte_patterns

- `scope`: `executable` (default) scans code sections (PE
  `IMAGE_SCN_MEM_EXECUTE`, ELF `SHF_EXECINSTR`, Mach-O instruction sections).
  `all` scans every file-backed section. Files without recognisable headers
  are scanned whole (`scanned.scope: "file"`).
- `max_matches` (1–1000, default 16) bounds the matches returned per pattern.
  `total_matches` counts every match, up to 100000.
- `file`: format, architecture, preferred image base and the sections used to
  map offsets. Malformed headers are reported in `layout_error` and the file is
  scanned raw.
- Each match gives its file offset, link-time address, RVA (address minus the
  image base), section and matched bytes.
- `displacements`: each run of exactly four `??` bytes is read as a
  little-endian rel32 measured from the end of the run, with the resolved
  target address and its section. For `48 8B 05 ?? ?? ?? ??`
  (`mov rax, [rip+disp32]`) or `E8 ?? ?? ?? ??` (`call rel32`) this is the
  static variable or function the instruction refers to, which is how modders
  re-find a static pointer after an update. It is wrong for instructions with
  an immediate after the displacement.

Every overlapping match is reported, as Cheat Engine's AOB scan does.
radare2's `/x` resumes after each hit and can report fewer.

## inspect_cheat_table

The result contains:

- `entries`: each memory record with its group path, value type, stored address
  expression (split into `module` and `module_offset` when it is
  `module+offset`), pointer `offsets` as stored, group flag, hotkey count and
  child count. Cheat Engine applies stored offsets from last to first.
- `scripts`: for each Auto Assembler script, its `aobscan`, `aobscanmodule` and
  `aobscanregion` signatures, `assert(address, bytes)` checks, registered
  symbols and allocation count. Scripts are summarized, never executed.
- `symbols`, `structures` (dissected structure elements with offsets, types,
  sizes and descriptions) and the size of the table's Lua script.
- `binary_check` (with `binary_path`): every signature re-scanned across the
  module's file-backed sections. `applies` is false when an `aobscanmodule`
  names a different module. Every `assert(module+offset, bytes)` whose module
  matches is compared with the bytes at that RVA. Assert checks map RVAs
  through PE section headers, so they need a PE module.

## Boundaries

- Scans see the file as stored. Packed, encrypted or runtime-patched code
  differs in memory; use a dump of the running module when the file is
  protected.
- Addresses use the preferred image base; add the runtime slide for a live
  process.
- Tables up to 64 MiB and binaries up to 1 GiB are read into memory; up to
  5000 table entries are returned.

## Verification

`tests/boundary/providers/patterns/patterns.test.ts` checks a PE32+ image and
a Cheat Engine 7.5-style table built in source, and the radare2 ELF fixture.
Scans of real binaries were cross-checked against radare2 6.2.4 `/x` searches
restricted to executable maps. On a Windows x64 launcher (`w64.exe` from
distlib) the match counts (250 and 38), addresses, `call` targets and
RIP-relative `lea` targets agreed. On `/usr/bin/echo` the counts agreed (81).
On a 32-bit launcher, REA+ reported 1370 overlapping `E8 ?? ?? ?? ??` matches
where radare2 reported 1355 non-overlapping ones. The table reader follows
Cheat Engine 7 table XML and was not round-tripped through Cheat Engine itself.
