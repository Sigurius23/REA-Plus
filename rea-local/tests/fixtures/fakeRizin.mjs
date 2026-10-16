// Deterministic stand-in for Rizin 0.9.1 in -q0 pipe mode. Replies are
// recorded from the real engine on tests/fixtures/radare2Elf.ts after `aaa`;
// any other command is rejected so tests cannot rely on unmodeled behavior.
import { statSync } from "node:fs";

const scenario = process.env.REA_FAKE_RADARE2_SCENARIO ?? "ready";
const version = process.env.REA_FAKE_RADARE2_VERSION ?? "0.9.1";
const COMMIT = "c3a90e9226d977f58f4e9c75f78fa6b07afe13c7";

// Rizin names the address `offset`; check_key is `main`, the entry's first call.
const AFLJ =
  '[{"offset":4194560,"name":"entry0","size":14,"is-pure":false,"realsz":14,"noreturn":false,"stackframe":0,"calltype":"amd64","cost":7,"cc":0,"loops":0,"bits":64,"type":"fcn","nbbs":1,"edges":1,"ebbs":0,"signature":"entry0(int argc, char **argv, char **envp);","minbound":4194560,"maxbound":4194574,"callrefs":[{"from":4194560,"to":4194574,"type":"CALL"}],"datarefs":[],"indegree":0,"outdegree":1,"nlocals":0,"nargs":3,"stackvars":[],"regvars":[{"name":"argc","arg":true,"type":"int","storage":{"type":"reg","reg":"rdi"}},{"name":"envp","arg":true,"type":"char **","storage":{"type":"reg","reg":"rdx"}},{"name":"argv","arg":true,"type":"char **","storage":{"type":"reg","reg":"rsi"}}]},{"offset":4194574,"name":"main","size":13,"is-pure":false,"realsz":13,"noreturn":false,"stackframe":0,"calltype":"amd64","cost":7,"cc":1,"loops":0,"bits":64,"type":"sym","nbbs":1,"edges":0,"ebbs":1,"signature":"int main(int argc, char **argv, char **envp);","minbound":4194574,"maxbound":4194587,"callrefs":[{"from":4194581,"to":4194587,"type":"CALL"}],"datarefs":[{"from":4194574,"to":4194624,"type":"DATA"}],"codexrefs":[{"from":4194560,"to":4194574,"type":"CALL"}],"dataxrefs":[],"indegree":1,"outdegree":1,"nlocals":0,"nargs":1,"stackvars":[],"regvars":[{"name":"argc","arg":true,"type":"int","storage":{"type":"reg","reg":"rdi"}}]},{"offset":4194587,"name":"sym.helper","size":5,"is-pure":true,"realsz":5,"noreturn":false,"stackframe":0,"calltype":"amd64","cost":4,"cc":1,"loops":0,"bits":64,"type":"sym","nbbs":1,"edges":0,"ebbs":1,"signature":"sym.helper(int64_t arg1);","minbound":4194587,"maxbound":4194592,"codexrefs":[{"from":4194581,"to":4194587,"type":"CALL"}],"dataxrefs":[],"indegree":1,"outdegree":0,"nlocals":0,"nargs":1,"stackvars":[],"regvars":[{"name":"arg1","arg":true,"type":"int64_t","storage":{"type":"reg","reg":"rdi"}}]}]';
const ISJ =
  '[{"name":"check_key","flagname":"sym.check_key","realname":"check_key","ordinal":1,"bind":"LOCAL","size":13,"type":"FUNC","vaddr":4194574,"paddr":270,"is_imported":false,"lib":""},{"name":"helper","flagname":"sym.helper","realname":"helper","ordinal":2,"bind":"LOCAL","size":5,"type":"FUNC","vaddr":4194587,"paddr":283,"is_imported":false,"lib":""},{"name":"secret","flagname":"obj.secret","realname":"secret","ordinal":3,"bind":"LOCAL","size":14,"type":"OBJ","vaddr":4194624,"paddr":320,"is_imported":false,"lib":""},{"name":"_start","flagname":"sym._start","realname":"_start","ordinal":4,"bind":"GLOBAL","size":14,"type":"FUNC","vaddr":4194560,"paddr":256,"is_imported":false,"lib":""}]';
const MAIN_AFIJ =
  '[{"offset":4194574,"name":"main","size":13,"is-pure":false,"realsz":13,"noreturn":false,"stackframe":0,"calltype":"amd64","cost":7,"cc":1,"loops":0,"bits":64,"type":"sym","nbbs":1,"edges":0,"ebbs":1,"signature":"int main(int argc, char **argv, char **envp);","minbound":4194574,"maxbound":4194587,"callrefs":[{"from":4194581,"to":4194587,"type":"CALL"}],"datarefs":[{"from":4194574,"to":4194624,"type":"DATA"}],"codexrefs":[{"from":4194560,"to":4194574,"type":"CALL"}],"dataxrefs":[],"indegree":1,"outdegree":1,"nlocals":0,"nargs":1,"stackvars":[],"regvars":[{"name":"argc","arg":true,"type":"int","storage":{"type":"reg","reg":"rdi"}}]}]';
const REPLIES = new Map([
  ["aflj", AFLJ],
  ["isj", ISJ],
  // Rizin's axtj names no containing function.
  ["axtj @ 0x40011b", '[{"from":4194581,"to":4194587,"type":"CALL"}]'],
  ["afij @ 0x400115", MAIN_AFIJ],
  ["afij @ 0x40010e", MAIN_AFIJ],
  [
    "afbj @ 0x40010e",
    '[{"opaddr":4194574,"addr":4194574,"size":13,"inputs":0,"outputs":0,"ninstr":3,"traced":true}]',
  ],
  [
    "afvlj @ 0x40010e",
    '{"reg":[{"name":"argc","arg":true,"type":"int","storage":{"type":"reg","reg":"rdi"}}]}',
  ],
  // Bottom-most map first, exclusive ends.
  [
    "omlj",
    '[{"map":1,"fd":3,"delta":0,"from":4194304,"to":4195336,"perm":"r-x","name":"fmap.LOAD0"},{"map":2,"fd":4,"delta":0,"from":5242880,"to":5242944,"perm":"rw-","name":"mmap.LOAD1"}]',
  ],
  ["p8 5 @ 0x40011b", "8d447f01c3"],
]);

const args = process.argv.slice(2);
if (args[0] === "-v") {
  process.stdout.write(`rizin ${version} @ linux-x86-64\ncommit: ${COMMIT}\n`);
  process.exit(0);
}

const target = args.at(-1);
const reply = (text) => process.stdout.write(`${text}\0`);

const handle = (command) => {
  switch (command) {
    case "ver":
      return reply(
        `${scenario === "version-drift" ? "0.9.0" : version} @ linux-x86-64\ncommit: ${COMMIT}\n`,
      );
    case "ij":
      return reply(
        JSON.stringify({
          core: {
            file: target,
            fd: 3,
            size: statSync(target).size,
            format: "elf64",
          },
          bin: { arch: "x86", bits: 64, baddr: 4194304, endian: "LE" },
        }),
      );
    case "aa":
    case "aaa":
    case "aaaa":
      return reply("");
    default:
      if (REPLIES.has(command)) return reply(REPLIES.get(command));
      process.stderr.write(`unmodeled rizin command: ${command}\n`);
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
