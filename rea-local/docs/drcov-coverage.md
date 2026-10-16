# Coverage logs and differential coverage

`inspect_coverage_log` / `inspect-coverage-log` reads a drcov basic-block
coverage log and reports which modules and blocks executed. Give it a second
log of the same program without the behavior you care about, and it keeps
only blocks whose bytes that baseline never ran. Recording "idle" and "jump"
runs of a game and diffing them narrows the jump handler to a few blocks.

REA+ does not trace anything itself. It needs no tool configuration; it parses
logs you already recorded.

## Recording logs

[DynamoRIO](https://dynamorio.org)'s drcov client:

```sh
drrun -t drcov -logdir /traces/idle -- ./Game.x86_64
drrun -t drcov -logdir /traces/jump -- ./Game.x86_64   # perform the action
```

On Windows use `drrun.exe` from `bin64` (or `bin32` for 32-bit games). Frida
scripts that write Lighthouse-compatible drcov logs (such as
`frida-drcov.py`) work too, which covers Android and iOS processes.

```sh
rea inspect-coverage-log /traces/jump/drcov.Game.x86_64.1234.0000.proc.log --json
rea inspect-coverage-log /traces/jump/drcov.*.log --baseline_path /traces/idle/drcov.*.log \
  --module GameAssembly.so --json
```

```json
{
  "name": "inspect_coverage_log",
  "arguments": {
    "path": "/traces/jump/drcov.Game.x86_64.1234.0000.proc.log",
    "baseline_path": "/traces/idle/drcov.Game.x86_64.1200.0000.proc.log",
    "module": "GameAssembly.so"
  }
}
```

## What the result contains

- `log` and `baseline`: path, SHA-256, size, drcov version and flavor, module
  table version, whether the block table is binary or text, and the number of
  block entries.
- `modules`: every module with at least one executed block, ordered by unique
  blocks, with its runtime range, unique blocks and covered bytes. With a
  baseline, `new_blocks` counts blocks that have bytes the baseline did not
  execute, and `baseline_covered_bytes` gives the baseline's coverage of the
  same module path.
- `selected_module` and `blocks`: with `module` (an exact path or a file name),
  the module's segments and a page of its unique blocks in address order.
  `offset` and `limit` (1–5000, default 500) page them, and `page.total`
  counts all of them.

Each block has three addresses:

- `image_offset`: the offset from the module's first mapped segment. This is
  stable across ASLR and runs, and it is what baseline comparison uses.
- `static_address`: the segment's preferred (link-time) base plus the block
  offset, comparable with a disassembler that loads the file at its preferred
  base. DynamoRIO 7.0 and later write this column on Linux. For a PIE or
  shared library the preferred base is usually 0, so
  `static_address` equals `image_offset`. Older logs and Frida logs leave it
  null; add `image_offset` to the image base your disassembler uses.
- `runtime_address`: the address in the traced process.

Open the module with a binary provider (radare2, Ghidra, IDA, Binary Ninja or
Hopper) and pass `static_address`, or your image base plus `image_offset`, to
`resolve_containing_procedure` to name the functions that ran.

## Supported logs

- drcov versions 2 and 3, with module table versions 2 through 5: Linux and
  Windows column sets, including `containing_id`, `offset`, `preferred_base`,
  `checksum` and `timestamp`. Module paths may contain commas.
- Binary block tables and the text tables `drcov -dump_text` writes.
- Module table version 1 (DynamoRIO before 6.1) is rejected.

## Boundaries

- drcov records whether a block ran, not how often or in what order. Block
  sizes are DynamoRIO's dynamic blocks, which can differ from a
  disassembler's static blocks.
- Baseline comparison matches modules by exact path and blocks by image
  offset, so both runs must load the same module file. Comparison is by
  covered bytes: a block counts as new when any of its bytes is new, even if
  the baseline split the same code into different blocks.
- A log is a caller-supplied record. REA+ cannot confirm the traced binary is
  the file you later disassemble; compare paths, sizes and your own hashes.
- Logs up to 512 MiB are read into memory.

## Verification

Unit tests parse logs in DynamoRIO 11.2's Linux layout and Windows and Frida
column sets, binary and text block tables, and malformed headers and tables.
`tests/boundary/providers/drcov/coverageLog.test.ts` runs the service on logs
built in source and, when `REA_VERIFY_DYNAMORIO_HOME` is set on Linux x86-64,
traces `tests/fixtures/coverageElf.ts` with real DynamoRIO drcov. That
fixture branches on its argument count, and the diff of a run with an argument
against one without returns exactly the call block and the called function.
This passed with DynamoRIO 11.2.0 on Linux x86-64. Windows and macOS drcov
logs, 32-bit logs and Frida-generated logs have only been checked against
synthesized samples.
