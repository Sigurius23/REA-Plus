/**
 * Deterministic x86-64 Linux executable whose executed blocks depend on argc,
 * for differential-coverage tests. One read/execute PT_LOAD maps the file at
 * 0x400000; there are no section headers.
 *
 *   _start: cmp qword [rsp], 1; je exit; call bonus
 *   exit:   xor edi, edi; mov eax, 60; syscall
 *   bonus:  mov eax, 42; ret
 *
 * Without arguments only `_start` and `exit` run; with one argument the call
 * block and `bonus` run as well.
 */
export const COVERAGE_ELF_BASE = 0x400000;

const START = 0x100;
const CALL = START + 7;
const EXIT = CALL + 5;
const BONUS = EXIT + 9;

/** Image offsets of DynamoRIO's dynamic blocks for each run. */
export const COVERAGE_ELF_BLOCKS = Object.freeze({
  start: { offset: START, size: 7 },
  call: { offset: CALL, size: 5 },
  exit: { offset: EXIT, size: 9 },
  bonus: { offset: BONUS, size: 6 },
});

const CODE = Buffer.from([
  // _start: cmp qword [rsp], 1; je exit
  0x48,
  0x83,
  0x3c,
  0x24,
  0x01,
  0x74,
  0x05,
  // call bonus
  0xe8,
  BONUS - (CALL + 5),
  0x00,
  0x00,
  0x00,
  // exit: xor edi, edi; mov eax, 60; syscall
  0x31,
  0xff,
  0xb8,
  0x3c,
  0x00,
  0x00,
  0x00,
  0x0f,
  0x05,
  // bonus: mov eax, 42; ret
  0xb8,
  0x2a,
  0x00,
  0x00,
  0x00,
  0xc3,
]);

/** Build the executable; every call returns an identical buffer. */
export const createCoverageElf = (): Buffer => {
  const file = Buffer.alloc(START + CODE.length);
  file.write("\x7fELF", 0, "latin1");
  file.writeUInt8(2, 4);
  file.writeUInt8(1, 5);
  file.writeUInt8(1, 6);
  file.writeUInt16LE(2, 16);
  file.writeUInt16LE(62, 18);
  file.writeUInt32LE(1, 20);
  file.writeBigUInt64LE(BigInt(COVERAGE_ELF_BASE + START), 24);
  file.writeBigUInt64LE(64n, 32);
  file.writeUInt16LE(64, 52);
  file.writeUInt16LE(56, 54);
  file.writeUInt16LE(1, 56);
  file.writeUInt16LE(64, 58);
  // PT_LOAD r-x mapping the whole file.
  file.writeUInt32LE(1, 64);
  file.writeUInt32LE(5, 68);
  file.writeBigUInt64LE(0n, 72);
  file.writeBigUInt64LE(BigInt(COVERAGE_ELF_BASE), 80);
  file.writeBigUInt64LE(BigInt(COVERAGE_ELF_BASE), 88);
  file.writeBigUInt64LE(BigInt(file.length), 96);
  file.writeBigUInt64LE(BigInt(file.length), 104);
  file.writeBigUInt64LE(0x1000n, 112);
  CODE.copy(file, START);
  return file;
};
