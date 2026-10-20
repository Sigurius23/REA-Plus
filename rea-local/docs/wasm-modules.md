# WebAssembly modules

`inspect_wasm_module` / `inspect-wasm-module` decodes a WebAssembly module
the way web game builds ship it: a plain `.wasm`, or the gzip- and
Brotli-compressed `.wasm.gz`, `.wasm.br` and Unity `.unityweb` files. It
needs no WABT, Binaryen or JavaScript engine, and nothing is compiled or run.

It answers the first questions about a web build's code: what built it,
which functions exist and what they call, and what crosses into JavaScript.
For WAT text use `inspect_wasm_artifact` with WABT
([guide](./wasm-artifacts.md)).

```sh
rea inspect-wasm-module ~/Games/web/Build/game.wasm.br --json
rea inspect-wasm-module game.wasm --query damage --json
rea inspect-wasm-module game.wasm --view calls --function 1234 --json
rea inspect-wasm-module game.wasm --view strings --query http --json
```

```json
{
  "name": "inspect_wasm_module",
  "arguments": {
    "path": "/games/web/Build/game.wasm",
    "view": "calls",
    "function": "il2cpp_init"
  }
}
```

## What the result contains

- `module`: SHA-256 and size of the file and of the decompressed module, the
  compression, and the module name from the name section.
- `toolchain`:
  - `producers` and `target_features` as the toolchain recorded them;
  - `detected`: Emscripten (also minified builds that import everything from
    module `a`), Unity WebGL, IL2CPP, Godot, wasm-bindgen, Rust, Bevy, Go,
    TinyGo, .NET, WASI and Clang. These come from import and export naming,
    producers entries, and engine strings in data such as `UnityEngine.`,
    `Godot Engine` or `/rustc/`;
  - `debug`: whether the build kept a name section, DWARF sections, a source
    map URL or an external debug file.
- `summary`: counts of types, imports, functions, exports, tables, globals
  and data segments; memories with their limits; code and data sizes; the
  start function; and how many bodies did not decode.
- `page` and one view, filtered by `query`:
  - `functions` (default): index, name, signature, body offset and size,
    locals, how many functions it calls directly, how many indirect calls
    it makes, and how many functions call it. `function` keeps one.
  - `calls`: with `function` (an index or a name), the functions it calls
    directly and the functions that call it, with call-site counts.
  - `imports` and `exports`: the module's boundary with JavaScript. Exports
    carry the exported function's name.
  - `data`: segments with mode, memory, load address and size.
  - `strings`: printable runs in data segments with their memory address.
    `min_string_length` sets the shortest run (default 6).
  - `sections` and `custom`: the section table, and custom sections with the
    text of small text-only ones, such as `sourceMappingURL`.

Offsets are into the decompressed module. Function names come from the name
section when the build kept it. Otherwise they come from exports, and
imported functions are named `module.name`. Release builds usually strip the
name section, so most functions are only an index. Following calls from the
exports and imports is often the quickest way in.

## Boundaries

- Only core modules (version 1) are read. Component-model binaries are
  refused.
- `call_indirect` and `call_ref` targets depend on runtime tables, so they
  are counted, not resolved.
- Bodies are decoded for the core instruction set plus SIMD, threads, bulk
  memory, reference types, exception handling, tail calls and GC. A body
  with any other opcode is marked `decoded: false`, and its calls up to that
  point are kept.
- Strings are printable ASCII runs, not proven string values. UTF-16 text
  and strings built at runtime are not found.
- Files over 512 MiB, or decompressing past 1 GiB, are refused.

## Verification

`tests/boundary/providers/wasmmodule/wasmModule.test.ts` assembles a module
byte by byte. It has an Emscripten-style import, imported memory and global,
functions that call each other directly and through a table, SIMD and
bulk-memory instructions, active and passive data, and the name, producers,
target_features, `sourceMappingURL`, `external_debug_info` and DWARF custom
sections. Node's V8 validates the module, and its imports, exports and
custom sections are checked against V8's own decoding. The tests read the
module plain, gzip- and Brotli-compressed, and refuse text, truncated
modules, broken gzip streams and component binaries.

`REA_VERIFY_WASM_DIR` points the tests at a folder of real modules. Every
module is decoded and checked against V8: the same imports and exports in
the same order, every custom section at its size, and no undecoded bodies.
`REA_VERIFY_GZIP_BIN` and `REA_VERIFY_BROTLI_BIN` also compress a real
module with the `gzip` and `brotli` commands and check that it reads back
the same.

The lane passed on ten builds from itch.io HTML5 games:

- four Godot exports, one built with minified imports;
- four Unity WebGL builds with IL2CPP, which had been shipped as `.wasm.br`
  or `.wasm.gz`;
- one Rust/Bevy game built with wasm-bindgen, and one other Rust game.

The largest had over 110,000 functions. Every body decoded, and V8 agreed on
every import, export and custom section.
