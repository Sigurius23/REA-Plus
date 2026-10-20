# Library function identification

`identify_library_functions` / `identify-library-functions` names the
statically linked library code in a stripped ELF or PE binary, the way IDA's
FLIRT does. Typical targets are libc, zlib, OpenSSL, Lua or a game engine's
runtime. It needs the static libraries or object files the binary may have
linked. It needs no analysis provider and executes nothing.

Each library function becomes a signature: its whole body as bytes. The bytes
the linker rewrites are wildcards:

- every relocated field;
- on x86-64, the instruction bytes before a GOT or initial-exec TLS field,
  which linkers relax into another instruction;
- general- and local-dynamic TLS sequences.

The binary's code is scanned for every signature by an 8-byte anchor.
FLIRT stops at a 32-byte prefix; here every fixed byte must match.

```sh
rea identify-library-functions ~/games/engine-stripped \
  --library /usr/lib/x86_64-linux-gnu/libc.a --library ~/zlib/libz.a --json
rea identify-library-functions engine.exe --library zlib.lib --view functions --json
```

```json
{
  "name": "identify_library_functions",
  "arguments": {
    "path": "/games/engine-stripped",
    "libraries": ["/usr/lib/x86_64-linux-gnu/libc.a", "/libs/libz.a"],
    "view": "functions"
  }
}
```

## How matches are settled

- **Unique**: one function (or one function with aliases, such as `fclose`
  and `_IO_new_fclose`, reported together) has those bytes.
- **Resolved**: several functions have the same bytes, and one is chosen by:
  - **calls**: a call must land on a function identified under the name the
    object calls. `adler32` and `crc32` are the same jump to different
    routines;
  - **strings**: a string the object refers to must be the string the
    binary refers to there;
  - **layout**: functions of one object section keep their relative offsets
    when linked, so an identified neighbour places byte-identical siblings
    such as `gztell` and `gztell64`.
- **Ambiguous**: still undecided. Every candidate name is reported.

A hit that starts inside a longer hit is dropped. Each function reports how
many of its references were confirmed, contradicted or left unchecked (a
call into code nothing identified, or data that is not a string).

## What the result contains

- `file`: path, SHA-256, size, format and machine of the binary.
- `libraries`: per library, its kind (archive or object), object format,
  machine, members, unreadable members, functions, functions too short to
  sign, signatures, and functions identified from it.
- `summary`: identified, unique, resolved and ambiguous counts; bytes of code
  scanned and bytes identified.
- `page` and, in the `functions` view, each identified function: address
  range, names, status, library and member, whether it is static, fixed
  bytes, and reference checks.

## Boundaries

- Only code compiled identically is found. A library built by another
  compiler, version or flags matches only the functions that came out
  byte for byte the same. Pass the libraries the binary was most likely built
  with.
- Functions with fewer than `min_bytes` (default 16) fixed bytes, or without
  8 fixed bytes in a row, get no signature. Most thunks and tiny accessors
  are among them.
- Objects are read from ELF (x86, x86-64, ARM, AArch64) and COFF files, alone
  or in `ar` archives (`.a`, `.lib`). Mach-O objects, LLVM bitcode (LTO
  builds) and MSVC import-only members contribute nothing.
- On ARM and AArch64 a relocated instruction is wildcarded whole. Linker
  relaxations other than x86-64's GOT and TLS ones, link-time optimization,
  and hot-patch padding change bytes and prevent a match.
- Targets are ELF and PE images. Their file-backed segments or sections are
  scanned. Packed or encrypted code is not found until unpacked.
- Binaries up to 1 GiB and libraries up to 512 MiB are read.

## Verification

`tests/boundary/providers/libid/libraryIdentification.test.ts` builds a
GNU archive of three ELF objects byte by byte, with a long member name, and
an executable that linked them. All ten functions must be named, including:

- two wrappers resolved by their calls;
- two printers resolved by their strings;
- two byte-identical functions resolved by layout;
- an alias pair reported together.

`tests/boundary/providers/libid/libraryIdentificationReal.test.ts` builds
zlib (`REA_VERIFY_LIBID_ZLIB`) into a static library and links minigzip
against it twice: stripped for identification and unstripped as the answer
key.

- GCC (`REA_VERIFY_LIBID_CC`), ELF: every zlib function is named, none
  wrongly.
- MinGW-w64 (`REA_VERIFY_LIBID_MINGW`), PE from COFF objects: every zlib
  function is named, none wrongly.
- A fully static build with glibc's `libc.a` (`REA_VERIFY_LIBID_LIBC`):
  nothing is named wrongly, and at least 95% of signed functions are found.
  With GCC 13 and glibc 2.39 that was 977 of 991, the rest being shared
  `.cold` fragments left ambiguous. Scanning the dynamically linked build
  with `libc.a` must find nothing.

zlib 1.2.13 signatures against a binary linked with zlib 1.3.1 named the 96
functions that compiled identically, and none wrongly. Other compilers, MSVC
libraries, ARM targets and large proprietary binaries were not measured.
