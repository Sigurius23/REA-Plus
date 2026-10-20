# Crash minidumps

`inspect_minidump` / `inspect-minidump` reads a crash minidump and explains it
the way a first WinDbg pass would: which thread faulted, with what exception,
at which module and offset, and which modules were loaded. It reads Windows
`.dmp` files (Windows Error Reporting, procdump, Task Manager, WinDbg
`.dump`, and the crash reporters many games ship) and Breakpad or Crashpad
minidumps from Windows, Linux, Android and macOS.

The dump is parsed, never opened in a debugger. REA+ needs no tool
configuration and does not download symbols.

```sh
rea inspect-minidump /crashes/Game_2026-10-15.dmp --json
rea inspect-minidump /crashes/Game_2026-10-15.dmp --thread_id 4120 --stack_scan_limit 64 --json
```

```json
{
  "name": "inspect_minidump",
  "arguments": { "path": "/crashes/Game_2026-10-15.dmp" }
}
```

## What the result contains

- `dump`: path, SHA-256, size, creation time, `MINIDUMP_TYPE` flags, and every
  stream with its size and whether REA+ decoded it, did not interpret it, or
  found it malformed. A malformed stream does not stop the rest of the dump
  from being decoded.
- `system`: CPU architecture, OS, OS version and build, service pack (the
  kernel release on Linux), processor count and CPU vendor.
- `process`: process ID and creation time when the dump records them.
- `exception`: thread, code and its name (an NTSTATUS such as
  `EXCEPTION_ACCESS_VIOLATION`, a Linux signal such as `SIGSEGV / SEGV_MAPERR`,
  or a Mach exception such as `EXC_BAD_ACCESS / KERN_INVALID_ADDRESS`), flags,
  address and parameters. For Windows access violations and in-page errors,
  `access` gives the access kind (read, write or execute) and the data address.
  `instruction_pointer` and `instruction_module` give the faulting instruction
  from the exception context as module+offset, with the registers at the
  fault.
- `threads`: every thread with its name (Windows 10 thread names), whether it
  faulted, its stack range, and its instruction and stack pointers, the
  instruction pointer as module+offset.
- `selected_thread`: registers and a stack scan for the exception thread, or
  for `thread_id`. The scan walks the captured stack upward from the stack
  pointer and lists slots holding addresses inside module images. These are
  return-address candidates, the same heuristic WinDbg's `dps` relies on, not
  an unwound call stack. Values are return addresses; unwinders such as
  `minidump-stackwalk` show the call site one byte earlier.
- `modules`: path, base, size, timestamp, checksum, file and product versions,
  and identifiers for symbol lookup. `code_id` (Windows: `TimeDateStamp`
  followed by `SizeOfImage`) locates the binary on a symbol server, and
  `debug.debug_id` with `debug.file` locates the PDB or debug file. Breakpad
  ELF modules report their GNU build ID and the matching Breakpad debug ID.
- `unloaded_modules`, and a `memory` summary (ranges, bytes, and whether this
  is a full-memory dump).

Take `instruction_module` and stack-scan offsets to a binary provider: open the
same module build with radare2, Ghidra or another provider and inspect the
function at base plus offset.

## Boundaries

- No unwinding, symbolization or disassembly. Use the module identifiers to
  fetch symbols yourself and a binary provider to read the code.
- Registers are decoded for x86, AMD64, ARM64 and 32-bit ARM contexts.
- Stream types REA+ does not interpret (handles, tokens, Linux `/proc` copies,
  Crashpad annotations) are listed but not decoded.
- Dumps up to 2 GiB are read into memory.

## Verification

`tests/boundary/providers/minidump/minidump.test.ts` checks a Windows x64 dump
built in source. When `REA_VERIFY_MINIDUMP_DIR` points at
[rust-minidump](https://github.com/rust-minidump/rust-minidump)'s `testdata`,
it also checks six real dumps against values from rust-minidump's
`minidump-stackwalk` 0.27.0: Windows XP x86, Windows 10 x64 (one of them a
full-memory dump), Linux x64 (Breakpad) and macOS x64 (Crashpad). The
exception, crashing thread, faulting module+offset, thread and module counts,
process ID and debug IDs agreed. A fuzzed dump whose stream directory points
outside the file is reported, not fatal. ARM64 and ARM contexts and NB10
CodeView records are covered only by unit tests on synthesized bytes.
