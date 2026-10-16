import {
  inspectLogicCaptureInputSchema,
  logicCaptureSchema,
} from "../../domain/logic/logicCapture.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free logic-analyzer session reader with optional sigrok decoders. */
export const LOGIC_TOOL_CONTRACTS = [
  {
    name: "inspect_logic_capture",
    ...toolContractMetadata("inspect_logic_capture"),
    kind: "artifact-provider",
    description:
      "Read a sigrok logic-analyzer session (.sr from PulseView or sigrok-cli) and return Evidence: samplerate, duration, every logic channel's levels, transitions, shortest pulse and bit-rate estimate, and analog channel ranges. Add a protocol decoder stack (for example uart with {rx: 'D0'} and {baudrate: 115200}, spi then spiflash, or i2c) to run caller-supplied sigrok-cli 0.7 (REA_SIGROK_CLI) and get time-stamped annotations per selected class; classes whose annotations are single hex bytes (UART, SPI, I2C data) are also joined into a byte stream with UTF-8 text, which recovers serial console logs and flash traffic. Captures are parsed, never replayed to hardware.",
    inputSchema: inspectLogicCaptureInputSchema,
    outputSchema: evidenceResultOf(logicCaptureSchema),
    examples: [
      {
        title: "Recover a UART boot log",
        input: {
          path: "/captures/board-boot.sr",
          decoders: [
            {
              id: "uart",
              channels: { rx: "D0" },
              options: { baudrate: 115200 },
            },
          ],
          annotations: ["rx-data"],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
