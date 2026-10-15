import { z } from "zod";

import { jsonValueSchema } from "../jsonValue.js";

const deviceIdSchema = z
  .string()
  .min(1)
  .max(512)
  .refine(
    (value) => !value.includes(String.fromCharCode(0)),
    "NUL is not permitted",
  );
const targetNameSchema = z
  .string()
  .min(1)
  .max(512)
  .refine(
    (value) =>
      !value.includes(String.fromCharCode(0)) &&
      !value.includes(String.fromCharCode(10)) &&
      !value.includes(String.fromCharCode(13)),
    "Target names cannot contain NUL or line breaks",
  );
const runtimeScriptSchema = z
  .string()
  .min(1)
  .max(65_536)
  .refine(
    (value) => !value.includes(String.fromCharCode(0)),
    "NUL is not permitted in a Frida script",
  );
const objectionCommandSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine(
    (value) =>
      !value.includes(String.fromCharCode(0)) &&
      !value.includes(String.fromCharCode(10)) &&
      !value.includes(String.fromCharCode(13)),
    "An Objection command must be one line without NUL",
  );

export const mobileRuntimeInputSchemas = {
  list_frida_devices: z.strictObject({}),
  list_frida_processes: z.strictObject({
    device_id: deviceIdSchema.optional(),
  }),
  run_frida_script: z.strictObject({
    device_id: deviceIdSchema.optional(),
    pid: z.number().int().min(1).max(2_147_483_647),
    script: runtimeScriptSchema,
    observation_ms: z.number().int().min(100).max(30_000).default(5_000),
    confirm_runtime_code_execution: z.literal(true),
  }),
  run_objection_command: z.strictObject({
    target: targetNameSchema,
    device_serial: deviceIdSchema.optional(),
    command: objectionCommandSchema,
    timeout_ms: z.number().int().min(1).max(120_000).default(30_000),
    confirm_runtime_command_execution: z.literal(true),
  }),
} as const;

export type MobileRuntimeOperation = keyof typeof mobileRuntimeInputSchemas;

const device = z.strictObject({
  id: z.string().min(1),
  name: z.string().min(1),
  type: z.string().min(1),
});
const process = z.strictObject({
  pid: z.number().int().min(1),
  name: z.string().min(1),
  parameters: jsonValueSchema.nullable(),
});
const runtimeMessage = z.strictObject({
  type: z.string().min(1),
  payload: jsonValueSchema.optional(),
  text: z.string().optional(),
  stack: z.string().optional(),
  data_bytes: z.number().int().min(0).optional(),
  data_sha256: z
    .string()
    .regex(/^sha256:[a-f0-9]{64}$/u)
    .optional(),
  truncated: z.boolean().optional(),
});

export const mobileRuntimeResultSchemas = {
  list_frida_devices: z.strictObject({
    frida_version: z.string().nullable(),
    python_executable_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    devices: z.array(device),
    omitted_device_count: z.number().int().min(0),
  }),
  list_frida_processes: z.strictObject({
    frida_version: z.string().nullable(),
    python_executable_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    device: device,
    processes: z.array(process),
    omitted_process_count: z.number().int().min(0),
  }),
  run_frida_script: z.strictObject({
    frida_version: z.string().nullable(),
    python_executable_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    device: device,
    process: z.strictObject({
      pid: z.number().int().min(1),
      name: z.string().min(1),
    }),
    script_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    script_bytes: z.number().int().min(1),
    observation_ms: z.number().int().min(100).max(30_000),
    messages: z.array(runtimeMessage),
    omitted_message_count: z.number().int().min(0),
    messages_truncated: z.boolean(),
    script_unloaded: z.boolean(),
    detached: z.boolean(),
  }),
  run_objection_command: z.strictObject({
    target: z.string().min(1),
    device_serial: z.string().nullable(),
    command_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    command_bytes: z.number().int().min(1),
    executable_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
    stdout: z.string(),
    stderr: z.string(),
    stdout_bytes: z.number().int().min(0),
    stderr_bytes: z.number().int().min(0),
    output_truncated: z.boolean(),
    exit_code: z.number().int().nullable(),
    signal: z.string().nullable(),
    timed_out: z.boolean(),
  }),
} satisfies Readonly<Record<MobileRuntimeOperation, z.ZodType>>;

export const mobileRuntimeRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("list_frida_devices"),
    input: mobileRuntimeInputSchemas.list_frida_devices,
  }),
  z.strictObject({
    operation: z.literal("list_frida_processes"),
    input: mobileRuntimeInputSchemas.list_frida_processes,
  }),
  z.strictObject({
    operation: z.literal("run_frida_script"),
    input: mobileRuntimeInputSchemas.run_frida_script,
  }),
  z.strictObject({
    operation: z.literal("run_objection_command"),
    input: mobileRuntimeInputSchemas.run_objection_command,
  }),
]);

export type MobileRuntimeRequest = z.infer<typeof mobileRuntimeRequestSchema>;
