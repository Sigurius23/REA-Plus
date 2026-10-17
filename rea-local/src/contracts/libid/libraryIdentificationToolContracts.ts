import {
  identifyLibraryFunctionsInputSchema,
  libraryIdentificationSchema,
} from "../../domain/libid/libraryIdentification.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Offline FLIRT-style library identification with CLI/MCP parity; nothing is executed. */
export const LIBRARY_IDENTIFICATION_TOOL_CONTRACTS = [
  {
    name: "identify_library_functions",
    ...toolContractMetadata("identify_library_functions"),
    kind: "artifact-provider",
    description:
      "Name the statically linked library functions (libc, zlib, OpenSSL, Lua, a game engine's runtime) in a stripped ELF or PE binary from the static libraries or object files it may have linked, FLIRT-style, and return Evidence. Each library function's whole body becomes a byte signature with the bytes the linker relocates as wildcards (ELF and COFF objects, alone or in .a/.lib archives); the binary's code is scanned for them. Functions with the same bytes are told apart by the functions they call, the strings they refer to and their object's layout; aliases are reported together. Returns each identified function's address range, names, library member, status and reference checks, and per-library counts. No analysis provider is needed and nothing is executed.",
    inputSchema: identifyLibraryFunctionsInputSchema,
    outputSchema: evidenceResultOf(libraryIdentificationSchema),
    examples: [
      {
        title: "Find zlib in a stripped game binary",
        input: {
          path: "/games/engine.exe",
          libraries: ["/libs/zlib-1.3.1/libz.lib"],
        },
      },
      {
        title: "List glibc functions in a static executable",
        input: {
          path: "/bin/tool-static",
          libraries: ["/usr/lib/x86_64-linux-gnu/libc.a"],
          view: "functions",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
