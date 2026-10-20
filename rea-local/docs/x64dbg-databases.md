# x64dbg databases

`inspect_x64dbg_database` / `inspect-x64dbg-database` reads the database
x64dbg saves for each debugged program (`db/<program>.dd64` or `.dd32`). It
carries the labels, comments, bookmarks, function and loop ranges,
breakpoints, cross-references and watch expressions from a
reverse-engineering session. Given the game executable, it also places them
in the file and checks saved breakpoints against it. A game update that
moved the code shows up as mismatches.

Nothing is attached to, debugged or run.

```sh
rea inspect-x64dbg-database ~/x64dbg/release/x64/db/game.exe.dd64 --json
rea inspect-x64dbg-database game.exe.dd64 --view comments --query health --json
rea inspect-x64dbg-database game.exe.dd64 --view breakpoints --module_path ~/Games/game/game.exe --json
```

```json
{
  "name": "inspect_x64dbg_database",
  "arguments": {
    "path": "/x64dbg/db/game.exe.dd64",
    "view": "functions",
    "module": "game.exe"
  }
}
```

## What the result contains

- `database`:
  - whether it was LZ4-compressed, and the JSON size;
  - the debuggee hash x64dbg stores (`murmurhash`);
  - the top-level sections present, and the modules its entries name;
  - the session notes and init script;
  - plugins that saved data.
- `module_file` (with `module_path`): name, SHA-256, format and image base.
- `summary`: counts per section, and with `module_path` the number of
  breakpoints whose original bytes no longer match.
- `page` and one view, filtered by `module` and `query`:
  - `labels`, `comments`, `bookmarks`: module, address, text, and whether it
    was set by hand or by analysis. Older `auto…` lists count as analysis.
  - `functions`, `arguments`, `loops`: module, start, end, instruction
    count, parent, and loop depth.
  - `breakpoints`: software, hardware, memory, DLL and exception breakpoints
    with name, enabled state, break, log and command conditions and text,
    fast-resume and silent flags. Software breakpoints also give the two
    original bytes x64dbg read under them.
  - `xrefs`: an address and the addresses that reference it, with their type.
  - `watch`: name, expression, data type and watchdog mode.

Addresses are as x64dbg stores them: relative to the named module's base,
or absolute when no module is named.

With `module_path`, entries for the module of that file name gain a file
offset and section, mapped through the PE (or ELF/Mach-O) section table.
Software breakpoints there gain `bytes_match`: whether the file still holds
the bytes x64dbg recorded.

## Boundaries

- Trace records, encode maps, address colours and per-module hashes are
  listed in `sections` but not decoded.
- Only the module named by `module_path` gets file offsets. Entries in other
  modules, such as system DLLs, are listed as stored.
- Databases over 256 MiB, or decompressing past 512 MiB, are refused.
  Module files may be up to 1 GiB.

## Verification

`tests/boundary/providers/x64dbg/x64dbgDatabase.test.ts` builds a database
the way x64dbg's `DbSave` writes it, read from x64dbg's source. It has
`0x%llX` hex strings, module-relative addresses, a legacy `autolabels` list,
the breakpoint fields of `BpCacheSave`, watches, notes and plugin data.

The tests read the database:

- as plain JSON;
- compressed in x64dbg's LZ4 legacy frame, split into several blocks;
- against a small PE game executable, where one breakpoint's bytes match and
  one does not.

Truncated frames, non-JSON files and a relative `module_path` are refused.

`REA_VERIFY_LZ4_BIN`, pointed at the `lz4` command (1.9.4 tested), checks the
LZ4 side independently. It compresses databases with `lz4 -l`, which writes
the same legacy frame as x64dbg's `lz4file`, including an 18 MB database
that spans three 8 MiB blocks, and reads them back.

No database written by x64dbg itself was available here. The JSON layout
comes from x64dbg's source, not from a saved file.
