import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const seconds = z.number().nonnegative();

/** sigrok identifiers: decoder ids, channel roles and option keys. */
const identifier = z.string().regex(/^[a-z0-9_]{1,40}$/u);
/** Annotation class ids, such as rx-data. */
const annotationClass = z.string().regex(/^[a-z0-9_\-]{1,40}$/u);
/** Values sigrok-cli's -P syntax can carry without separators. */
const optionValue = z.union([
  z.number().finite(),
  z.string().regex(/^[A-Za-z0-9_.+\-]{1,64}$/u),
]);

export const LOGIC_ANNOTATION_LIMIT = 20_000;

export const inspectLogicCaptureInputSchema = z.strictObject({
  path: z.string().min(1).describe("Absolute sigrok session (.sr) path"),
  decoders: z
    .array(
      z.strictObject({
        id: identifier.describe("sigrok decoder id, such as uart, spi or i2c"),
        channels: z
          .record(identifier, z.string().min(1).max(64))
          .default({})
          .describe(
            "Decoder channel role to capture channel name, such as {rx: 'D0'}; only the first decoder takes channels.",
          ),
        options: z
          .record(identifier, optionValue)
          .default({})
          .describe("Decoder options, such as {baudrate: 115200}."),
      }),
    )
    .min(1)
    .max(4)
    .optional()
    .describe(
      "Protocol decoder stack, bottom first (for example spi then spiflash); needs caller-supplied sigrok-cli.",
    ),
  annotations: z
    .array(annotationClass)
    .min(1)
    .max(8)
    .optional()
    .describe(
      "Annotation classes of the top decoder to return, such as rx-data; omit for all rows unlabelled.",
    ),
  annotation_limit: z
    .number()
    .int()
    .min(1)
    .max(LOGIC_ANNOTATION_LIMIT)
    .default(1000)
    .describe("Most annotations to return per class."),
});

const annotation = z.strictObject({
  class: z
    .string()
    .nullable()
    .describe("Annotation class; null when classes were not selected."),
  decoder: z.string().describe("Decoder instance, such as uart-1."),
  start_sample: count,
  end_sample: count,
  start_s: seconds,
  end_s: seconds,
  text: z.string(),
});

export const logicCaptureSchema = z.strictObject({
  capture: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    sigrok_version: z.string().nullable(),
    samplerate_hz: z.number().positive(),
    samples: count,
    duration_s: seconds,
    unitsize: z.number().int().min(1).max(8),
  }),
  channels: z.array(
    z.strictObject({
      name: z.string(),
      index: count,
      initial_level: z.union([z.literal(0), z.literal(1)]),
      final_level: z.union([z.literal(0), z.literal(1)]),
      transitions: count,
      first_transition_s: seconds.nullable(),
      high_fraction: z.number().min(0).max(1),
      shortest_pulse_s: seconds
        .nullable()
        .describe("Shortest complete high or low run between two edges."),
      estimated_bit_rate: z
        .number()
        .nullable()
        .describe(
          "Samplerate over the mean length of pulses shorter than 1.5 shortest pulses: a UART baud-rate or clock-rate estimate, not a measurement.",
        ),
    }),
  ),
  analog: z.array(
    z.strictObject({
      name: z.string(),
      index: count,
      samples: count,
      min: z.number(),
      max: z.number(),
      mean: z.number(),
    }),
  ),
  decode: z
    .strictObject({
      stack: z.array(z.string()).describe("The -P argument sigrok-cli ran."),
      classes: z.array(
        z.strictObject({ id: z.string(), description: z.string() }),
      ),
      annotations: z.array(annotation),
      totals: z.array(
        z.strictObject({
          class: z.string().nullable(),
          total: count,
          returned: count,
        }),
      ),
      byte_streams: z
        .array(
          z.strictObject({
            class: z.string(),
            bytes: count,
            hex: z.string().regex(/^(?:[0-9a-f]{2})*$/u),
            text: z
              .string()
              .describe("UTF-8 decoding; invalid bytes become U+FFFD."),
            truncated: z.boolean(),
          }),
        )
        .describe(
          "Classes whose every annotation is one hex byte (UART, SPI and I2C data), joined in order.",
        ),
      tool_profile: z.strictObject({
        tool: z.literal("sigrok-cli"),
        version: z.string(),
        libsigrokdecode: z.string().nullable(),
        executable_path: z.string().min(1),
        executable_sha256: digest,
        arguments: z.array(z.array(z.string())),
        timeout_ms: z.number().int().positive(),
      }),
    })
    .nullable(),
  limitations: z.array(z.string()),
});

export type InspectLogicCaptureInput = z.output<
  typeof inspectLogicCaptureInputSchema
>;
export type LogicCapture = z.output<typeof logicCaptureSchema>;
export type LogicAnnotation = z.output<typeof annotation>;
