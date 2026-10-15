# Frida and Objection runtime instrumentation

REA+ provides an optional, caller-supplied adapter for [Frida](https://github.com/frida/frida) and [Objection](https://github.com/sensepost/objection). These are runtime tools, not REA+-owned engines or MCP servers. REA+ does not install, vendor, update, or verify either upstream tool.

## Configure

Set one or both variables to absolute paths:

- `REA_FRIDA_PYTHON_PATH`: Python interpreter with the Frida Python bindings already installed. A dedicated virtual environment is recommended.
- `REA_OBJECTION_CMD_PATH`: the caller-installed Objection executable.

The child receives only a small host environment allowlist (`PATH`, home/temp variables, and Windows system variables); arbitrary REA+-process environment variables and credentials are not forwarded. On Windows, Frida's private request-file directory requires the verified native private-DACL capability. If REA+ cannot establish that boundary, Frida operations fail closed.

REA+ does not use a host shell. Frida requests are written to a private per-call file and removed after the helper exits. The Python helper and Objection executable are hashed for Evidence provenance. Frida scripts and Objection commands themselves are represented in Evidence parameters by SHA-256 and UTF-8 byte length; their source text is not copied into Evidence parameters.

## Tools

- `list_frida_devices` enumerates Frida-visible devices.
- `list_frida_processes` lists bounded process metadata for a selected device (or the local device when omitted). PIDs are ephemeral; enumerate again before using one.
- `run_frida_script` attaches to one explicit PID, executes a caller-supplied Frida JavaScript script, and captures a bounded observation interval. Every call must set `confirm_runtime_code_execution: true`.
- `run_objection_command` invokes one caller-supplied Objection command for a named target, optionally with a device serial. Every call must set `confirm_runtime_command_execution: true`. The command is passed as one argument to `objection --name TARGET [--serial SERIAL] run COMMAND`, without a host shell; Objection's own command language remains active.

The tools produce REA+ Evidence, but a device/process observation has no artifact subject unless that association is independently established. `run_frida_script` accepts one caller script, one PID, and an observation interval from 100 to 30,000 ms. Objection commands time out after a caller-selected interval capped at 120 seconds. The combined stdout/stderr capture budget is 512 KiB; overflow is reported as a resource-constraint error with bounded partial diagnostics. Frida message capture is further bounded to 128 messages and a 256 KiB aggregate message budget. Enumeration is capped at 128 devices and 512 processes.

## Runtime authority and safety

Frida scripts run inside the selected process with the attached runtime's authority. They may change process memory, behavior, UI state, files, or network activity, and may persist effects outside the process. Objection commands may have comparable effects on the target or device. **The explicit confirmation booleans are required because these operations are effectful; they are not a sandbox or a promise of reversibility.** The provider revalidates the request schema as defense in depth, so direct adapter calls cannot omit or set the confirmation field to false and reach the command runner. The Frida result reports whether script unload and process detachment were confirmed; if either is false, inspect the target before assuming the session is clean. A controller timeout cannot roll back script effects already applied to a target and may prevent REA+ from receiving cleanup status. Review the script or command and the target before confirming.

REA+ terminates only its owned helper/CLI process tree on cancellation or timeout, subject to the host's process-ownership guarantees. This bounds controller lifetime; it does not constrain code injected into another process. No device, app, or instrumentation server is started or installed by REA+.

## Verification status

No real Frida device or Objection CLI compatibility test was performed for this implementation. REA+ unit/contract tests verify request validation, provenance, registration, and lifecycle handling with recording runners; they do not prove compatibility with every Frida/Objection release or target platform. Test with the exact caller-selected versions and a controlled target before operational use.
