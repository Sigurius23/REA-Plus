// Deterministic stand-in for radare2 6.2.4 in -q0 pipe mode. Replies are
// recorded from the real engine on tests/fixtures/radare2Elf.ts; any other
// command is rejected so tests cannot rely on unmodeled behavior.
import { statSync } from "node:fs";

const scenario = process.env.REA_FAKE_RADARE2_SCENARIO ?? "ready";
const version = process.env.REA_FAKE_RADARE2_VERSION ?? "6.2.4";
const banner = (reported) =>
  `radare2 ${reported} +1 abi:152 @ linux-x86_64\n` +
  `birth: git.${reported} 2026-10-15__22:26:21\n` +
  "commit: 485e5e205b190fc297a2a95a6f982ff5d9f54039\n" +
  "options: gpl -O? cs:5 cl:2 make\n";

// Recorded from radare2 6.2.4 `aflj` after `aaa` on the fixture ELF.
const AFLJ =
  '[{"addr":4194560,"name":"entry0","size":14,"is-pure":"true","realsz":14,"noreturn":false,"recursive":false,"stackframe":0,"calltype":"amd64","cost":7,"cc":1,"bits":64,"type":"fcn","nbbs":1,"tracecov":0,"is-lineal":true,"ninstrs":4,"edges":0,"ebbs":1,"signature":"entry0 (int64_t arg1);","minaddr":4194560,"maxaddr":4194574,"maxbbins":4,"midbbins":4.000,"ratbbins":1.000,"indegree":0,"outdegree":1,"nlocals":0,"nargs":1,"difftype":"new"},{"addr":4194574,"name":"sym.check_key","size":13,"is-pure":"true","realsz":13,"noreturn":false,"recursive":false,"stackframe":0,"calltype":"amd64","cost":7,"cc":1,"bits":64,"type":"fcn","nbbs":1,"tracecov":0,"is-lineal":true,"ninstrs":3,"edges":0,"ebbs":1,"signature":"sym.check_key (int64_t arg1);","minaddr":4194574,"maxaddr":4194587,"maxbbins":3,"midbbins":3.000,"ratbbins":1.000,"indegree":1,"outdegree":1,"nlocals":0,"nargs":1,"difftype":"new"},{"addr":4194587,"name":"sym.helper","size":5,"is-pure":"true","realsz":5,"noreturn":false,"recursive":false,"stackframe":0,"calltype":"amd64","cost":4,"cc":1,"bits":64,"type":"fcn","nbbs":1,"tracecov":0,"is-lineal":true,"ninstrs":2,"edges":0,"ebbs":1,"signature":"sym.helper (int64_t arg1);","minaddr":4194587,"maxaddr":4194592,"maxbbins":2,"midbbins":2.000,"ratbbins":1.000,"indegree":1,"outdegree":0,"nlocals":0,"nargs":1,"difftype":"new"}]';

const args = process.argv.slice(2);
if (args[0] === "-v") {
  process.stdout.write(banner(version));
  process.exit(0);
}

const target = args.at(-1);
const reply = (text) => process.stdout.write(`${text}\0`);

const handle = (command) => {
  switch (command) {
    case "?V":
      return reply(banner(scenario === "version-drift" ? "6.0.0" : version));
    case "ij":
      return reply(
        JSON.stringify({
          core: {
            file: target,
            fd: 3,
            size: statSync(target).size,
            format: "elf64",
          },
          bin: { arch: "x86", bits: 64, baddr: 4194304, endian: "little" },
        }),
      );
    case "aa":
    case "aaa":
    case "aaaa":
      if (scenario === "hang-analysis") return undefined;
      if (scenario === "exit-analysis") {
        process.stderr.write("fake radare2 analysis crashed\n");
        process.exit(3);
      }
      return reply("");
    case "aflj":
      if (scenario === "hang-inventory") return undefined;
      return reply(AFLJ);
    default:
      process.stderr.write(`unmodeled radare2 command: ${command}\n`);
      process.exit(99);
  }
};

let pending = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  pending += chunk;
  for (let end = pending.indexOf("\n"); end >= 0; end = pending.indexOf("\n")) {
    const command = pending.slice(0, end);
    pending = pending.slice(end + 1);
    handle(command);
  }
});
process.stdin.on("end", () => process.exit(0));
reply("");
