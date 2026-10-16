# Lua bytecode

`inspect_lua_bytecode` / `inspect-lua-bytecode` decodes compiled Lua, the
form many games and mods ship their scripts in. It reads:

- PUC Lua 5.1, 5.2, 5.3 and 5.4 binary chunks, from `luac` or
  `string.dump`;
- LuaJIT 2.0 and 2.1 bytecode, from `luajit -b` or `string.dump`.

Nothing is loaded or run, and no Lua installation is needed.

The listing follows the compiler's own: operands appear as `luac -l` or
`luajit -bl` print them. So you can read REA+'s output side by side with
guides written for those tools.

```sh
rea inspect-lua-bytecode ~/Games/mod/scripts/main.luac --json
rea inspect-lua-bytecode main.luac --view instructions --function 0/3 --json
rea inspect-lua-bytecode main.luac --view constants --query http --json
rea inspect-lua-bytecode ~/Games/game/data.pak --view chunks --json
rea inspect-lua-bytecode data.pak --chunk_offset 81920 --json
```

```json
{
  "name": "inspect_lua_bytecode",
  "arguments": {
    "path": "/games/mod/scripts/main.luac",
    "view": "instructions",
    "function": "0/3"
  }
}
```

## What the result contains

- `file`: path, SHA-256 and size.
- `chunk`: where it starts and how long it is. Also:
  - the dialect and version byte, and the byte order;
  - the type sizes the header declares (`int`, `size_t`, `Instruction`,
    `lua_Integer`, `lua_Number`);
  - LuaJIT flags (`strip`, `ffi`, `fr2`, `big-endian`, `bitop`);
  - the chunk name (usually `@path/to/source.lua`), and whether debug
    information was stripped.
- `summary`: functions, instructions, constants, strings, locals and
  upvalues. Also how many functions got a name hint, and how many
  instructions have an opcode outside the dialect's table.
- `page` and one view, filtered by `function` and `query`:
  - `functions` (default): the function tree. Ids are paths: `0` is the main
    chunk, and `0/2` is its third child. Each row has a `name_hint`, the
    defining lines, parameters, vararg, stack size, and counts.
  - `instructions`: one row per instruction:
    - `pc` (1-based) and source `line`;
    - `op`, and `operands` as luac or luajit print them;
    - a `comment` naming referenced constants, upvalues and child
      functions, and the `target` of jumps and loops;
    - the raw `fields` (A, B, C, Bx, sBx, k, D...).
  - `constants`: type and value. Strings are kept exactly. Numbers are
    printed with `%.14g` like the compilers. LuaJIT's two pools, GC objects
    (`gc`) and numbers (`num`), stay separate.
  - `locals`: names with the pc range where each is live.
  - `upvalues`: names, and whether each is captured from the parent's
    registers or its upvalues. Lua 5.4 adds the variable kind.
  - `chunks`: every chunk signature in the file, each read where possible.
    Use it on archives, saves or executables that embed Lua, then select one
    with `chunk_offset`.

### Name hints

Bytecode records no function names. REA+ looks at what the code does with
each function right after creating it:

- stores it in a global (`SETGLOBAL`, `SETTABUP _ENV`, `GSET`);
- stores it in a table field (`SETTABLE`, `SETFIELD`, `TSETS`), whose table
  is traced back to a local, global or upvalue (`M.update`);
- keeps it in a named local (`local function inner`).

Anonymous callbacks get no hint. On the verification corpus below:

- 45% of Lua 5.1 functions got a hint, and about 54% for the other
  versions.
- 99.6–99.8% of hints named something on the function's defining source
  line.
- The rest were assignments split across lines, such as `x =` on one line
  and `function()` on the next.

## Boundaries

- Luau (Roblox), Ravi, Pluto and other derived bytecode formats are not
  read.
- Opcode names come from the stock tables. A game that shuffles opcodes or
  changes the chunk format, a common protection, decodes with wrong names
  or `UNKNOWN_` opcodes. `summary.unknown_opcodes` counts those.
- This is a disassembler, not a decompiler. It produces no Lua source.
- Stripped chunks keep no lines, local names or upvalue names.
- LuaJIT 2.0 dumps are decoded from LuaJIT 2.0's opcode table; only 2.1 was
  checked against a running LuaJIT. Dumps with the new `bitop` flag use
  LuaJIT's current opcode table.
- Files over 512 MiB are refused.

## Verification

`tests/boundary/providers/lua/luaBytecode.test.ts` assembles chunks byte by
byte, with opcode numbers taken from each version's `lopcodes.h` and
LuaJIT's `lj_bc.h`. They cover:

- Lua 5.1, little-endian and big-endian with a 4-byte `size_t`;
- Lua 5.3 with integer constants and `_ENV`;
- Lua 5.4 with varint sizes, absolute line info and `RETURN0`;
- LuaJIT 2.1, plain, stripped and big-endian, with a child prototype,
  string and number constants and local names.

The tests check name hints, embedded chunks found by `chunks`, and the
refusal of source text, Luau-like files, unknown versions, truncated and
corrupted chunks, and function or offset selections that do not exist.

`REA_VERIFY_LUA_SOURCES` points the tests at a folder of `.lua` files. Each
configured compiler (`REA_VERIFY_LUAC51` to `REA_VERIFY_LUAC54`,
`REA_VERIFY_LUAJIT`) builds every file with and without debug info and lists
the result with `luac -l -l` or `luajit -bl`. Per function, REA+ must then
match:

- the header and counts;
- every instruction's pc, line, opcode and operands;
- every constant, compared byte for byte;
- every local and upvalue;
- for LuaJIT, every string the listing shows.

The lane passed on 389 files from rxi/json.lua, lume, inspect.lua,
middleclass, Moses, Penlight, LuaRocks and Factorio's Lua game data (wube's
factorio-data). The compilers were Lua 5.1.5, 5.2.4, 5.3.6 and 5.4.6 and
LuaJIT 2.1 from Ubuntu's packages. That made 3,836 chunks, and every one
matched.
