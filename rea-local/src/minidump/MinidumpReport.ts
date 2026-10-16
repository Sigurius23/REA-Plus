import type {
  InspectMinidumpInput,
  Minidump,
  MinidumpModule,
} from "../domain/minidump/minidump.js";
import {
  accessDetails,
  hex,
  hex32,
  isoTime,
  memorySummary,
  ModuleIndex,
  registerRecord,
  scanStack,
} from "./MinidumpAnalysis.js";
import { readContext, type ThreadRegisters } from "./MinidumpContext.js";
import {
  MinidumpFile,
  MinidumpFormatError,
  STREAM_NAMES,
} from "./MinidumpFile.js";
import {
  architectureName,
  exceptionName,
  isWindowsPlatform,
  platformName,
} from "./MinidumpNames.js";
import {
  readException,
  readMemory64List,
  readMemoryList,
  readMiscInfo,
  readModules,
  readSystemInfo,
  readThreadNames,
  readThreads,
  readUnloadedModules,
  type RawModule,
  type RawThread,
} from "./MinidumpStreams.js";

/** A thread_id that names no recorded thread. */
export class MinidumpThreadNotFound extends Error {}

type StreamStatus = Minidump["dump"]["streams"][number];

/** Decode each stream independently so one malformed stream is reported, not fatal. */
class StreamDecoder {
  readonly statuses = new Map<
    number,
    Pick<StreamStatus, "status" | "message">
  >();

  constructor(readonly file: MinidumpFile) {}

  decode<T>(type: number, read: (file: MinidumpFile) => T, fallback: T): T {
    if (this.file.stream(type) === undefined) return fallback;
    try {
      const value = read(this.file);
      this.statuses.set(type, { status: "decoded", message: null });
      return value;
    } catch (cause: unknown) {
      if (!(cause instanceof MinidumpFormatError)) throw cause;
      this.statuses.set(type, { status: "malformed", message: cause.message });
      return fallback;
    }
  }

  streams(): StreamStatus[] {
    return this.file.streams.map(({ type, size, rva }) => ({
      type: STREAM_NAMES[type] ?? hex32(type),
      bytes: size,
      ...(rva + size > this.file.bytes.length
        ? {
            status: "malformed" as const,
            message: `The stream at 0x${rva.toString(16)} (+${String(size)} bytes) lies outside the dump.`,
          }
        : (this.statuses.get(type) ?? {
            status: "not-decoded" as const,
            message: null,
          })),
    }));
  }
}

const moduleRecord = (module: RawModule, windows: boolean): MinidumpModule => {
  const view = module.codeView;
  return {
    name: module.name,
    base: hex(module.base),
    size: module.size,
    end: hex(module.base + BigInt(module.size)),
    timestamp: isoTime(module.timestamp),
    checksum: hex32(module.checksum),
    file_version: module.fileVersion,
    product_version: module.productVersion,
    code_id:
      windows && module.timestamp !== 0
        ? `${module.timestamp.toString(16).toUpperCase().padStart(8, "0")}${module.size.toString(16)}`
        : null,
    debug:
      view === null
        ? null
        : {
            format: view.format,
            file: "pdb" in view ? view.pdb : null,
            guid: view.format === "RSDS" ? view.guid : null,
            age: "age" in view ? view.age : null,
            debug_id: "debugId" in view ? view.debugId : null,
            build_id: view.format === "ELF build ID" ? view.buildId : null,
          },
  };
};

const decodeAll = (file: MinidumpFile) => {
  const streams = new StreamDecoder(file);
  return {
    streams,
    system: streams.decode(7, readSystemInfo, null),
    threads: streams.decode(3, readThreads, null) ?? [],
    modules: streams.decode(4, readModules, null) ?? [],
    unloaded: streams.decode(14, readUnloadedModules, null) ?? [],
    exception: streams.decode(6, readException, null),
    misc: streams.decode(15, readMiscInfo, null),
    names: streams.decode(24, readThreadNames, new Map<number, string>()),
    memory: {
      ranges: [
        ...streams.decode(5, readMemoryList, []),
        ...streams.decode(9, readMemory64List, []),
      ],
      full: file.stream(9) !== undefined,
    },
  };
};

const safeContext = (
  file: MinidumpFile,
  location: Parameters<typeof readContext>[1],
): ThreadRegisters | null => {
  try {
    return readContext(file, location);
  } catch (cause: unknown) {
    if (cause instanceof MinidumpFormatError) return null;
    throw cause;
  }
};

interface ReportContext {
  readonly file: MinidumpFile;
  readonly decoded: ReturnType<typeof decodeAll>;
  readonly index: ModuleIndex;
  readonly platform: number | null;
  readonly exceptionContext: ThreadRegisters | null;
}

/** The exception thread's context is the one at the fault, not at dump time. */
const contextOf = (report: ReportContext, thread: RawThread) =>
  thread.id === report.decoded.exception?.threadId &&
  report.exceptionContext !== null
    ? report.exceptionContext
    : safeContext(report.file, thread.context);

const systemRecord = (
  system: ReturnType<typeof decodeAll>["system"],
): Minidump["system"] =>
  system === null
    ? null
    : {
        architecture: architectureName(system.architecture),
        os: platformName(system.platform),
        os_version: `${String(system.major)}.${String(system.minor)}.${String(system.build)}`,
        service_pack: system.csdVersion,
        processors: system.processors,
        cpu_vendor: system.cpuVendor,
      };

const exceptionRecord = (report: ReportContext): Minidump["exception"] => {
  const { exception } = report.decoded;
  if (exception === null) return null;
  const pointer = report.exceptionContext?.instructionPointer ?? null;
  return {
    thread_id: exception.threadId,
    code: hex32(exception.code),
    name: exceptionName(exception.code, exception.flags, report.platform),
    flags: hex32(exception.flags),
    address: hex(exception.address),
    parameters: exception.parameters.map(hex),
    access: isWindowsPlatform(report.platform)
      ? accessDetails(exception.code, exception.parameters)
      : null,
    instruction_pointer: pointer === null ? null : hex(pointer),
    instruction_module: report.index.locate(pointer),
    registers: registerRecord(report.exceptionContext),
  };
};

const threadRecord = (
  report: ReportContext,
  thread: RawThread,
): Minidump["threads"][number] => {
  const context = contextOf(report, thread);
  return {
    id: thread.id,
    name: report.decoded.names.get(thread.id) ?? null,
    crashed: thread.id === report.decoded.exception?.threadId,
    suspend_count: thread.suspendCount,
    priority: thread.priority | 0,
    teb: hex(thread.teb),
    stack: { start: hex(thread.stackStart), size: thread.stack.size },
    instruction_pointer:
      context === null ? null : hex(context.instructionPointer),
    stack_pointer: context === null ? null : hex(context.stackPointer),
    instruction_module: report.index.locate(
      context?.instructionPointer ?? null,
    ),
  };
};

/** The requested thread, or the exception thread by default. */
const selectedThread = (
  report: ReportContext,
  input: InspectMinidumpInput,
): Minidump["selected_thread"] => {
  const { threads, exception } = report.decoded;
  const wanted = input.thread_id ?? exception?.threadId;
  const thread = threads.find(({ id }) => id === wanted);
  if (input.thread_id !== undefined && thread === undefined)
    throw new MinidumpThreadNotFound(
      `No recorded thread has id ${String(input.thread_id)}; threads: ${threads
        .map(({ id }) => id)
        .slice(0, 40)
        .join(", ")}`,
    );
  if (thread === undefined) return null;
  const context = contextOf(report, thread);
  return {
    id: thread.id,
    registers: registerRecord(context),
    stack_scan: scanStack(report.file, thread, {
      context,
      modules: report.index,
      limit: input.stack_scan_limit,
    }),
  };
};

/** Build the normalized report for one parsed dump. */
export const buildMinidumpReport = (
  bytes: Buffer,
  input: InspectMinidumpInput,
  identity: { readonly sha256: string },
  limitations: readonly string[],
): Minidump => {
  const file = new MinidumpFile(bytes);
  const decoded = decodeAll(file);
  const report: ReportContext = {
    file,
    decoded,
    index: new ModuleIndex(decoded.modules),
    platform: decoded.system?.platform ?? null,
    exceptionContext:
      decoded.exception === null
        ? null
        : safeContext(file, decoded.exception.context),
  };
  const windows = isWindowsPlatform(report.platform);
  return {
    dump: {
      path: input.path,
      sha256: identity.sha256,
      bytes: bytes.length,
      created: isoTime(file.timestamp),
      flags: hex(file.flags),
      streams: decoded.streams.streams(),
    },
    system: systemRecord(decoded.system),
    process: {
      process_id: decoded.misc?.processId ?? null,
      created: isoTime(decoded.misc?.processCreateTime ?? null),
    },
    exception: exceptionRecord(report),
    selected_thread: selectedThread(report, input),
    threads: decoded.threads.map((thread) => threadRecord(report, thread)),
    modules: decoded.modules.map((module) => moduleRecord(module, windows)),
    unloaded_modules: decoded.unloaded.map((module) => ({
      name: module.name,
      base: hex(module.base),
      size: module.size,
      timestamp: isoTime(module.timestamp),
    })),
    memory: memorySummary(decoded.memory.ranges, decoded.memory.full),
    limitations: [...limitations],
  };
};
