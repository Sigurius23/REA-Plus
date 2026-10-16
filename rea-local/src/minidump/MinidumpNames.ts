/** MINIDUMP_SYSTEM_INFO ProcessorArchitecture, including Breakpad's values. */
const ARCHITECTURES: Readonly<Record<number, string>> = {
  0: "x86",
  1: "mips",
  3: "ppc",
  5: "arm",
  6: "ia64",
  9: "amd64",
  10: "x86-on-win64",
  12: "arm64",
  0x8001: "sparc",
  0x8002: "ppc64",
  0x8003: "arm64",
  0x8004: "mips64",
  0x8005: "riscv",
  0x8006: "riscv64",
};

/** PlatformId: Windows values and Breakpad/Crashpad extensions. */
const PLATFORMS: Readonly<Record<number, string>> = {
  0: "Windows (Win32s)",
  1: "Windows 9x",
  2: "Windows NT",
  3: "Windows CE",
  0x8000: "Unix",
  0x8101: "macOS",
  0x8102: "iOS",
  0x8201: "Linux",
  0x8202: "Solaris",
  0x8203: "Android",
  0x8204: "PS3",
  0x8205: "NaCl",
  0x8206: "Fuchsia",
};

const NTSTATUS: Readonly<Record<number, string>> = {
  0x40010005: "DBG_CONTROL_C",
  0x4000001f: "STATUS_WX86_BREAKPOINT",
  0x80000002: "EXCEPTION_DATATYPE_MISALIGNMENT",
  0x80000003: "EXCEPTION_BREAKPOINT",
  0x80000004: "EXCEPTION_SINGLE_STEP",
  0xc0000005: "EXCEPTION_ACCESS_VIOLATION",
  0xc0000006: "EXCEPTION_IN_PAGE_ERROR",
  0xc0000008: "EXCEPTION_INVALID_HANDLE",
  0xc000000d: "STATUS_INVALID_PARAMETER",
  0xc000001d: "EXCEPTION_ILLEGAL_INSTRUCTION",
  0xc0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
  0xc0000026: "EXCEPTION_INVALID_DISPOSITION",
  0xc000008c: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
  0xc000008d: "EXCEPTION_FLT_DENORMAL_OPERAND",
  0xc000008e: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
  0xc000008f: "EXCEPTION_FLT_INEXACT_RESULT",
  0xc0000090: "EXCEPTION_FLT_INVALID_OPERATION",
  0xc0000091: "EXCEPTION_FLT_OVERFLOW",
  0xc0000092: "EXCEPTION_FLT_STACK_CHECK",
  0xc0000093: "EXCEPTION_FLT_UNDERFLOW",
  0xc0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
  0xc0000095: "EXCEPTION_INT_OVERFLOW",
  0xc0000096: "EXCEPTION_PRIV_INSTRUCTION",
  0xc00000fd: "EXCEPTION_STACK_OVERFLOW",
  0xc000013a: "STATUS_CONTROL_C_EXIT",
  0xc0000142: "STATUS_DLL_INIT_FAILED",
  0xc0000374: "STATUS_HEAP_CORRUPTION",
  0xc0000409: "STATUS_STACK_BUFFER_OVERRUN",
  0xc0000417: "STATUS_INVALID_CRUNTIME_PARAMETER",
  0xc0000420: "STATUS_ASSERTION_FAILURE",
  0xe06d7363: "MSVC C++ exception (0xE06D7363)",
};

const LINUX_SIGNALS: Readonly<Record<number, string>> = {
  1: "SIGHUP",
  2: "SIGINT",
  3: "SIGQUIT",
  4: "SIGILL",
  5: "SIGTRAP",
  6: "SIGABRT",
  7: "SIGBUS",
  8: "SIGFPE",
  9: "SIGKILL",
  11: "SIGSEGV",
  13: "SIGPIPE",
  15: "SIGTERM",
  31: "SIGSYS",
  0xffffffff: "DUMP_REQUESTED",
};

const MAC_EXCEPTIONS: Readonly<Record<number, string>> = {
  1: "EXC_BAD_ACCESS",
  2: "EXC_BAD_INSTRUCTION",
  3: "EXC_ARITHMETIC",
  4: "EXC_EMULATION",
  5: "EXC_SOFTWARE",
  6: "EXC_BREAKPOINT",
  7: "EXC_SYSCALL",
  8: "EXC_MACH_SYSCALL",
  9: "EXC_RPC_ALERT",
  10: "EXC_CRASH",
  11: "EXC_RESOURCE",
  12: "EXC_GUARD",
};

export const architectureName = (value: number): string =>
  ARCHITECTURES[value] ?? `0x${value.toString(16)}`;

export const platformName = (value: number): string =>
  PLATFORMS[value] ?? `0x${value.toString(16)}`;

export const isWindowsPlatform = (value: number | null): boolean =>
  value !== null && value <= 3;

/** Fault sub-codes Breakpad and Crashpad store in ExceptionFlags. */
const SUBCODES: Readonly<Record<string, Readonly<Record<number, string>>>> = {
  SIGSEGV: { 1: "SEGV_MAPERR", 2: "SEGV_ACCERR" },
  SIGBUS: { 1: "BUS_ADRALN", 2: "BUS_ADRERR", 3: "BUS_OBJERR" },
  EXC_BAD_ACCESS: { 1: "KERN_INVALID_ADDRESS", 2: "KERN_PROTECTION_FAILURE" },
};

/** Exception names depend on the OS that wrote the dump. */
export const exceptionName = (
  code: number,
  flags: number,
  platform: number | null,
): string | null => {
  const linux = platform === 0x8201 || platform === 0x8203;
  const apple = platform === 0x8101 || platform === 0x8102;
  const name = linux
    ? LINUX_SIGNALS[code]
    : apple
      ? MAC_EXCEPTIONS[code]
      : NTSTATUS[code];
  if (name === undefined) return null;
  const subcode = linux || apple ? SUBCODES[name]?.[flags] : undefined;
  return subcode === undefined ? name : `${name} / ${subcode}`;
};
