# Logic-analyzer captures

`inspect_logic_capture` / `inspect-logic-capture` reads a
[sigrok](https://sigrok.org) session file (`.sr`, as saved by PulseView or
`sigrok-cli -o`) and describes every channel. With a protocol decoder stack,
it runs a caller-supplied `sigrok-cli` 0.7 to decode UART, SPI, I2C and the
other sigrok decoders. Single-byte data annotations are joined into a byte
stream, so a captured serial console comes back as text.

The capture is parsed and decoded offline; nothing talks to hardware.

```sh
rea inspect-logic-capture /captures/board-boot.sr --json
export REA_SIGROK_CLI=/usr/bin/sigrok-cli
rea inspect-logic-capture /captures/board-boot.sr \
  --decoders_json '[{"id":"uart","channels":{"rx":"D0"},"options":{"baudrate":115200}}]' \
  --annotations rx-data --json
```

```json
{
  "name": "inspect_logic_capture",
  "arguments": {
    "path": "/captures/flash-read.sr",
    "decoders": [
      {
        "id": "spi",
        "channels": { "clk": "D0", "mosi": "D1", "miso": "D2", "cs": "D3" }
      }
    ],
    "annotations": ["mosi-data", "miso-data"]
  }
}
```

## Requirements

Channel statistics need nothing beyond REA+. Decoding needs `REA_SIGROK_CLI`,
the absolute path of `sigrok-cli` 0.7 with libsigrokdecode and its Python
decoders (for example the `sigrok-cli` package on Debian and Ubuntu). REA+ runs
it as an owned process with a 300-second deadline per run and does not install
it.

## What the result contains

- `capture`: path, SHA-256, size, the sigrok version that wrote it, samplerate,
  sample count, duration and sample width.
- `channels`: for each logic channel, the initial and final levels, number of
  transitions, time of the first transition, fraction of time high, shortest
  complete pulse, and `estimated_bit_rate`. The estimate is the samplerate
  divided by the mean length of pulses shorter than 1.5 times the shortest
  one, which recovers a UART baud rate even when it does not divide the
  samplerate. For a clock line it is twice the clock frequency, since both
  half-periods count as pulses.
- `analog`: for each analog channel, sample count, minimum, maximum and mean.
- `decode` (with `decoders`):
  - `stack`: the `-P` argument that ran, such as `uart:rx=D0:baudrate=115200`.
    Decoders stack bottom first (for example `spi` then `spiflash`), and only
    the bottom decoder takes channels.
  - `classes`: the top decoder's annotation classes, from `sigrok-cli --show`.
  - `annotations`: decoder instance, start and end sample, start and end time,
    and text, for each selected class (`annotations`) up to `annotation_limit`
    per class. Without `annotations`, all of the top decoder's rows come back
    unlabelled (`class: null`), because sigrok-cli 0.7 does not print class
    names.
  - `totals`: annotations per class and how many were returned.
  - `byte_streams`: for each selected class whose every annotation is one hex
    byte (UART `rx-data`/`tx-data`, SPI `mosi-data`/`miso-data`, I2C data),
    the bytes in order as hex and UTF-8 text, up to 64 KiB inline.
  - `tool_profile`: sigrok-cli path, SHA-256, version, libsigrokdecode version
    and the exact arguments.

## Boundaries

- sigrok-cli 0.7 exits successfully even when a decoder fails to load or a
  required channel is missing, so REA+ treats any stderr output as a rejected
  stack and reports it. Channel names are checked against the capture first.
- Decoders interpret the samples with the channel mapping and options you
  give. A wrong baud rate, SPI mode or bit order produces plausible but wrong
  data; check `estimated_bit_rate` and the `warnings` classes.
- Only the session's first device is read. Saleae Logic and CSV exports need
  converting to a sigrok session first, for example with
  `sigrok-cli -I csv -i export.csv -o capture.sr`.
- Sessions up to 512 MiB of sample data are read into memory.

## Verification

`tests/fixtures/sigrokSession.ts` builds a session in source: UART text at
115200 baud and an SPI JEDEC-ID transfer sampled at 1 MHz, split over two logic
chunks, plus an analog ramp. `tests/boundary/providers/logic/logicCapture.test.ts`
checks the statistics without any tool, and checks decoding against a fake that
replays output recorded from sigrok-cli 0.7.2 with libsigrokdecode 0.5.3, which
also covers stderr-only failures, cancellation and unsupported releases. When
`REA_VERIFY_SIGROK_CLI` is set, the same decoding expectations run against the
real tool; they passed with sigrok-cli 0.7.2 on Linux x86-64. Captures from
real hardware and decoders other than UART and SPI have not been exercised
through REA+.
