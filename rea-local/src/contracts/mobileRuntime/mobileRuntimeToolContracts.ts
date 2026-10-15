import {
  mobileRuntimeInputSchemas,
  mobileRuntimeResultSchemas,
} from "../../domain/mobileRuntime/mobileRuntimeAnalysis.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import type { ToolContract } from "../toolContractTypes.js";

/** Explicitly configured Frida and Objection runtime-instrumentation tools. */
export const MOBILE_RUNTIME_TOOL_CONTRACTS = [
  {
    name: "list_frida_devices",
    ...toolContractMetadata("list_frida_devices"),
    description:
      "Enumerate devices visible to Frida using the caller-selected Python interpreter configured by REA_FRIDA_PYTHON_PATH (absolute; Frida Python bindings must already be installed). Starts a short-lived helper and may contact Frida device endpoints. REA+ does not install or update Frida.",
    kind: "mobile-runtime-provider",
    inputSchema: mobileRuntimeInputSchemas.list_frida_devices,
    outputSchema: evidenceResultOf(
      mobileRuntimeResultSchemas.list_frida_devices,
    ),
    examples: [{ title: "List Frida devices", input: {} }],
  },
  {
    name: "list_frida_processes",
    ...toolContractMetadata("list_frida_processes"),
    description:
      "List bounded process metadata on the selected Frida device (or the local device when device_id is omitted). Does not attach to a process or execute target code. Requires REA_FRIDA_PYTHON_PATH to name a caller-installed Python interpreter with Frida bindings.",
    kind: "mobile-runtime-provider",
    inputSchema: mobileRuntimeInputSchemas.list_frida_processes,
    outputSchema: evidenceResultOf(
      mobileRuntimeResultSchemas.list_frida_processes,
    ),
    examples: [
      { title: "List local-device processes", input: {} },
      {
        title: "List processes on a selected Frida device",
        input: { device_id: "usb" },
      },
    ],
  },
  {
    name: "run_frida_script",
    ...toolContractMetadata("run_frida_script"),
    description:
      "Attach to one caller-selected PID and run one caller-supplied Frida JavaScript script for a bounded observation interval. Requires confirm_runtime_code_execution=true on every call. Scripts execute inside the target process and may modify process state or persistent data; a controller timeout cannot roll back injected code or side effects. Script source is held only in a private per-call request file and is represented in Evidence by SHA-256 and byte length, not copied into Evidence parameters. Requires REA_FRIDA_PYTHON_PATH and Frida Python bindings; no host shell is used and REA+ does not install Frida.",
    kind: "mobile-runtime-provider",
    inputSchema: mobileRuntimeInputSchemas.run_frida_script,
    outputSchema: evidenceResultOf(mobileRuntimeResultSchemas.run_frida_script),
    examples: [
      {
        title: "Run an explicitly confirmed short Frida observation",
        input: {
          pid: 1234,
          script: "send({ message: 'hello from Frida' });",
          observation_ms: 1000,
          confirm_runtime_code_execution: true,
        },
      },
    ],
  },
  {
    name: "run_objection_command",
    ...toolContractMetadata("run_objection_command"),
    description:
      "Run one caller-selected Objection command against a named target, optionally selecting a device serial. Requires confirm_runtime_command_execution=true on every call. Objection's command language may modify the selected process, device, or application data; REA+ records bounded stdout/stderr and cannot roll back effects. The command is passed as one argument without a host shell. Configure REA_OBJECTION_CMD_PATH (absolute); REA+ does not install or update Objection.",
    kind: "mobile-runtime-provider",
    inputSchema: mobileRuntimeInputSchemas.run_objection_command,
    outputSchema: evidenceResultOf(
      mobileRuntimeResultSchemas.run_objection_command,
    ),
    examples: [
      {
        title: "Run a confirmed Objection query",
        input: {
          target: "com.example.app",
          command: "env",
          timeout_ms: 30_000,
          confirm_runtime_command_execution: true,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
