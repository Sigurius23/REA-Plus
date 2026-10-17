import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { LibraryIdentificationPort } from "../application/libid/LibraryIdentificationPort.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type {
  IdentifyLibraryFunctionsInput,
  LibraryIdentificationReport,
} from "../domain/libid/libraryIdentification.js";
import { err, ok, type Result } from "../domain/result.js";
import { librarySignatures, scanImage } from "./LibrarySignatures.js";
import { resolveHits, type Identified } from "./LibraryResolution.js";
import { readTargetImage } from "./TargetImage.js";

const OPERATION = "identify_library_functions";
const MAX_TARGET_BYTES = 1024 * 1024 * 1024;
const MAX_LIBRARY_BYTES = 512 * 1024 * 1024;

export const LIBRARY_IDENTIFICATION_PROVIDER_IDENTITY = {
  id: "library-identification",
  name: "REA+ library function identification",
  version: "1",
} as const;

const LIMITATIONS = [
  "A signature is a library function's whole body from the given objects, with the bytes the linker relocates as wildcards. A function is identified only where the binary holds exactly those bytes: a library built by another compiler, version or flags identifies only the functions that compiled identically.",
  "A hit that starts inside a longer hit is dropped. Functions with the same bytes are told apart by the functions they call, the strings they refer to and their object's layout; otherwise every candidate name is reported as ambiguous.",
  "Functions with fewer fixed bytes than min_bytes, such as thunks and tiny accessors, get no signature and are never identified.",
  "Objects are read from ELF (x86, x86-64, ARM, AArch64) and COFF files, alone or in ar archives (.a, .lib). Mach-O objects, LLVM bitcode and MSVC import-only members contribute nothing.",
  "x86-64 GOT and TLS relaxations are wildcarded; other linker relaxations, link-time optimization and hot-patch padding change bytes and prevent a match.",
];

const unreadable = (path: (string | number)[], message: string) =>
  new AnalysisInputError(OPERATION, undefined, [
    { path, reason: "invalid_value", message },
  ]);

const read = async (
  path: string,
  limit: number,
  at: (string | number)[],
): Promise<Result<Buffer, AnalysisError>> => {
  try {
    const info = await stat(path);
    if (!info.isFile()) return err(unreadable(at, `${path} is not a file.`));
    if (info.size > limit)
      return err(
        unreadable(at, `${path} is larger than ${String(limit)} bytes.`),
      );
    return ok(await readFile(path));
  } catch {
    return err(unreadable(at, `Cannot read ${path}.`));
  }
};

const hex = (value: bigint) => `0x${value.toString(16)}`;

const row = (item: Identified) => {
  const [first] = item.signatures;
  return {
    address: hex(item.address),
    end: hex(item.address + BigInt(item.length)),
    names: [...item.names],
    status: item.status,
    library: first === undefined ? "" : basename(first.library),
    member: first?.member ?? "",
    local: first?.local ?? false,
    fixed_bytes: first?.fixed ?? 0,
    references: {
      confirmed: item.confirmed,
      contradicted: item.contradicted,
      unchecked: item.unchecked,
    },
  };
};

/** Identify statically linked library functions by whole-body byte signatures. */
export class LibraryIdentifier implements LibraryIdentificationPort {
  async close(): Promise<void> {}

  async inspect(
    input: IdentifyLibraryFunctionsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    const target = await read(input.path, MAX_TARGET_BYTES, ["path"]);
    if (!target.ok) return target;
    const image = readTargetImage(target.value);
    if (image === null)
      return err(
        unreadable(["path"], `${input.path} is not an ELF or PE image.`),
      );
    const libraries = [];
    for (const [index, path] of input.libraries.entries()) {
      const data = await read(path, MAX_LIBRARY_BYTES, ["libraries", index]);
      if (!data.ok) return data;
      if (signal?.aborted === true)
        return err(new AnalysisCancelledError(OPERATION));
      libraries.push(
        librarySignatures(path, data.value, {
          minBytes: input.min_bytes,
          includeLocal: input.include_local,
        }),
      );
    }
    let identified: Identified[];
    try {
      identified = resolveHits(
        image,
        scanImage(
          image,
          libraries.flatMap(({ signatures }) => signatures),
          signal,
        ),
      );
    } catch (cause: unknown) {
      if (signal?.aborted === true)
        return err(new AnalysisCancelledError(OPERATION, { cause }));
      throw cause;
    }
    const sha256 = createHash("sha256").update(target.value).digest("hex");
    const report = this.#report(input, {
      image,
      identified,
      libraries,
      sha256,
      size: target.value.length,
    });
    return ok(
      createAnalysisExecution(
        report,
        LIBRARY_IDENTIFICATION_PROVIDER_IDENTITY,
        {
          limitations: [
            ...LIMITATIONS,
            ...libraries
              .filter(
                ({ machine }) =>
                  machine !== "unknown" && machine !== image.machine,
              )
              .map(
                ({ path, machine }) =>
                  `${basename(path)} holds ${machine} code but the binary is ${image.machine}; it cannot match.`,
              ),
          ],
          locations: [
            { kind: "artifact-path", path: input.path },
            ...input.libraries.map((path) => ({
              kind: "artifact-path" as const,
              path,
            })),
          ],
          subject: { path: input.path, sha256, format: image.format },
        },
      ),
    );
  }

  #report(
    input: IdentifyLibraryFunctionsInput,
    scan: {
      readonly image: NonNullable<ReturnType<typeof readTargetImage>>;
      readonly identified: readonly Identified[];
      readonly libraries: readonly ReturnType<typeof librarySignatures>[];
      readonly sha256: string;
      readonly size: number;
    },
  ): LibraryIdentificationReport {
    const { image, identified, libraries } = scan;
    const file = scan;
    const rows = identified.map(row);
    const query = input.query?.toLowerCase();
    const selected =
      input.view === "functions"
        ? rows.filter(
            (item) =>
              (input.status === undefined || item.status === input.status) &&
              (query === undefined ||
                [item.address, item.member, ...item.names].some((text) =>
                  text.toLowerCase().includes(query),
                )),
          )
        : [];
    const page = selected.slice(input.offset, input.offset + input.limit);
    const count = (status: string) =>
      identified.filter((item) => item.status === status).length;
    return {
      file: {
        path: input.path,
        sha256: file.sha256,
        size: file.size,
        format: image.format,
        machine: image.machine,
      },
      libraries: libraries.map((library) => ({
        path: library.path,
        kind: library.kind,
        format: library.format,
        machine: library.machine,
        members: library.members,
        unreadable_members: library.unreadable,
        functions: library.functions,
        short_functions: library.short,
        signatures: library.signatures.length,
        identified: identified.filter(({ signatures }) =>
          signatures.some((signature) => signature.library === library.path),
        ).length,
      })),
      summary: {
        identified: identified.length,
        unique: count("unique"),
        resolved: count("resolved"),
        ambiguous: count("ambiguous"),
        code_bytes: image.regions
          .filter(({ executable }) => executable)
          .reduce((sum, { bytes }) => sum + bytes.length, 0),
        identified_bytes: identified.reduce(
          (sum, { length }) => sum + length,
          0,
        ),
      },
      page: {
        view: input.view,
        status: input.status ?? null,
        query: input.query ?? null,
        offset: input.offset,
        limit: input.limit,
        total: selected.length,
        returned: page.length,
      },
      functions: page,
    };
  }
}
