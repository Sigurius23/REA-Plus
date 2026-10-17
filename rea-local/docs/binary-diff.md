# Binary diffing

`diff_binaries` / `diff-binaries` compares two builds of a native binary
function by function, the way BinDiff and Diaphora do. Use it for a security
patch, a game update or two firmware releases. It works on stripped builds.

Both builds are analyzed by the configured deep provider (Ghidra, IDA,
Binary Ninja, Hopper, radare2 or Rizin); see
[choosing a provider](../README.md#choosing-a-deep-analysis-provider). Each
build runs in its own session. Every listed function's `analyze_function`
report is reduced to features that survive relinking:

- instructions, with jump and call targets, addresses inside the image and
  provider-generated labels (`fcn.00401a30`, `FUN_00101234`, `sub_401000`)
  replaced by placeholders;
- mnemonic sequence;
- control-flow shape (block depths and degrees, BinDiff's MD-index);
- calls, in call-site order;
- referenced strings, immediate constants and named callees such as imports.

```sh
export REA_ANALYSIS_PROVIDER=radare2 REA_RADARE2_PATH=/usr/bin/r2
rea diff-binaries ~/builds/game-1.0 ~/builds/game-1.1 --json
rea diff-binaries game-1.0 game-1.1 --view unmatched --status added --json
rea diff-binaries game-1.0 game-1.1 --view function --function 0x401a30 --json
```

```json
{
  "name": "diff_binaries",
  "arguments": {
    "left": "/builds/game-1.0",
    "right": "/builds/game-1.1",
    "view": "functions",
    "status": "changed"
  }
}
```

## How functions are matched

Passes run in order. Each pass pairs only functions that are each other's
single best candidate:

1. **name**: the same name, when the provider did not make it up from the
   address (imports, exports, symbols, `main`). Turn off with `names: false`.
2. **identical**: the same normalized instructions (six or more).
3. **mnemonics**: the same mnemonic sequence, such as a function whose only
   change is a constant.
4. **fingerprint**: the same control-flow shape with the same strings,
   constants and named callees.
5. **call-graph**: callers and callees of matched pairs. Candidates are
   ranked by similarity and by how many of their matched neighbours
   correspond. Identical thunks to different routines are told apart this
   way.
6. **call-order**: an unmatched callee at the same place in two matched
   callers' call sequences. Most of the smaller body's instructions must
   appear in the other, so a function changed in place is paired but one
   replaced by an unrelated function is not.
7. **similarity**: the remaining functions of similar size, by weighted
   similarity of instructions, mnemonic pairs, shape, strings, constants and
   calls.

Weak matches need agreeing neighbours:

- A pair whose matched neighbours mostly disagree is never made.
- A pair with no matched neighbours needs a similarity of at least 0.8.
- `threshold` (default 0.5) is the lowest similarity otherwise.

## What the result contains

- `left`, `right`: each build's path, SHA-256, format, analysis provider and
  profile digest, and how many functions were listed, analyzed and failed.
- `summary`: matched, identical, changed, removed and added counts, and
  matches per method.
- `page` and one view:
  - `summary`: the least similar changed functions first.
  - `functions`: matched pairs in address order. Each pair has its method,
    similarity and call-graph agreement, and instruction, block and edge
    counts on both sides. It also lists changed lines and the calls,
    strings and constants added or removed. Calls are compared through
    the match, so a callee that only moved is not a change.
  - `unmatched`: functions found in only one build (`removed` or `added`),
    with their named calls and strings.
  - `function`: one function, selected by address or name in either build.
    Its pair row and an aligned instruction listing (`same`, `removed`,
    `added`) use the provider's original text.

Analysis of each build is cached by SHA-256, so paging through views and
functions analyzes each build once per server or CLI process.

## Boundaries

- Every match is an inference. A pair does not prove the two functions come
  from the same source. A function the provider split, merged or did not
  find in one build appears as removed or added.
- Register allocation, instruction scheduling and inlining changes count as
  changed lines. Compiler or flag changes between builds lower similarity
  throughout.
- Both builds must be routed to the same provider; ELF against PE is
  refused.
- Cost is one `analyze_function` per function per build. radare2 diffs
  zlib's minigzip (105 functions a build) in about 20 seconds and the Lua
  interpreter (about 550) in about a minute. Ghidra also decompiles each
  function, which takes longer. `max_functions` (default 3000) caps each
  build.
- The similarity pass compares at most 4,000,000 pairs; the summary says
  when it stopped early.
- Calls, strings and constants list at most 16 items per pair. A listing
  stops at 4,000 rows, or when its two sides need more than 2,000 edits.

## Verification

`tests/boundary/providers/bindiff/binaryDiff.test.ts` drives the tool
through a fixture provider. Two builds move every function, change one
constant and one call, remove one function and add another, and keep two
identical thunks to different routines. Every pair, the thunks' call-graph
match, both unmatched functions and the aligned listing must come back.

`tests/boundary/providers/bindiff/binaryDiffReal.test.ts` compiles
programs with `REA_VERIFY_BINDIFF_CC`. It strips each build for the diff and
keeps an unstripped copy whose symbols are the answer key. The diff runs
through radare2 (`REA_VERIFY_RADARE2_PATH`) and Rizin
(`REA_VERIFY_RIZIN_PATH`), with name matching off:

- A two-version game-like program: every function both builds share is
  matched correctly. `update_player`, whose body radare2 merges with a new
  function, is matched by call order. The removed and added functions are
  reported.
- `REA_VERIFY_BINDIFF_ZLIB` (zlib 1.2.13 and 1.3.1 checkouts) builds
  minigzip at `-O2`. With radare2 6.2.4, all 75 functions with symbols in
  both builds matched and none wrong.
- `REA_VERIFY_BINDIFF_LUA` (Lua 5.4.0 and 5.4.6 checkouts) builds the
  interpreter, four years of changes apart. With radare2 6.2.4, 426 of 446
  functions matched correctly. Six pairs disagree with the symbols. Four of
  them follow source renames or splits (`luaE_enterCcall` became
  `luaE_incCstack`, `mainposition` became `mainpositionTV`).

All lanes passed with radare2 6.2.4 and Rizin 0.9.1 on Linux x86-64 with
GCC 13. Other providers, compilers, architectures and very large binaries
were not measured.
