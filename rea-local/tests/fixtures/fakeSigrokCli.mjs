// Deterministic stand-in for sigrok-cli 0.7.2 (libsigrokdecode 0.5.3). Every
// output was recorded from the real CLI on tests/fixtures/sigrokSession.ts;
// other inputs fail the way sigrok-cli does, on stderr with exit 0.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const scenario = process.env.REA_FAKE_SIGROK_SCENARIO ?? "ready";
const FIXTURE_SHA256 =
  "8935f923946bcddf754611dd6b9db5dd42fff3d0928ae609d84bb908ef26bdca";

const RECORDED = {
  "--version":
    "sigrok-cli 0.7.2\n\nLibraries and features:\n- libsigrok 0.5.2/5:1:1 (rt: 0.5.2/5:1:1).\n - Libs:\n  - glib 2.80.0 (rt: 2.80.0/8000:0)\n  - libzip 1.7.3\n  - libserialport 0.1.1/1:0:1 (rt: 0.1.1/1:0:1)\n  - libusb-1.0 1.0.27.11882 API 0x0100010a\n  - hidapi 0.14.0\n  - bluez 5.72\n  - libftdi 1.5\n  - Host: x86_64-pc-linux-gnu, little-endian.\n  - SCPI backends: TCP, serial, USBTMC.\n- libsigrokdecode 0.5.3/6:1:2 (rt: 0.5.3/6:1:2).\n - Libs:\n  - glib 2.80.0 (rt: 2.80.0/8000:0)\n  - Python 3.12.2 / 0x30c02f0 (API 1013, ABI 3)\n  - Host: x86_64-pc-linux-gnu, little-endian.\n",
  "-P uart --show":
    "ID: uart\nName: UART\nLong name: Universal Asynchronous Receiver/Transmitter\nDescription: Asynchronous, serial bus.\nLicense: gplv2+\nPossible decoder input IDs:\n- logic\nPossible decoder output IDs:\n- uart\nDecoder tags:\nAnnotation classes:\n- rx-data: RX data\n- tx-data: TX data\n- rx-start: RX start bits\n- tx-start: TX start bits\n- rx-parity-ok: RX parity OK bits\n- tx-parity-ok: TX parity OK bits\n- rx-parity-err: RX parity error bits\n- tx-parity-err: TX parity error bits\n- rx-stop: RX stop bits\n- tx-stop: TX stop bits\n- rx-warnings: RX warnings\n- tx-warnings: TX warnings\n- rx-data-bits: RX data bits\n- tx-data-bits: TX data bits\n- rx-break: RX break\n- tx-break: TX break\n- rx-packet: RX packet\n- tx-packet: TX packet\nAnnotation rows:\n- rx-data-bits (RX bits): rx-data-bits\n- rx-data (RX): rx-data, rx-start, rx-parity-ok, rx-parity-err, rx-stop\n- rx-warnings (RX warnings): rx-warnings\n- rx-break (RX break): rx-break\n- rx-packets (RX packets): rx-packet\n- tx-data-bits (TX bits): tx-data-bits\n- tx-data (TX): tx-data, tx-start, tx-parity-ok, tx-parity-err, tx-stop\n- tx-warnings (TX warnings): tx-warnings\n- tx-break (TX break): tx-break\n- tx-packets (TX packets): tx-packet\nBinary classes:\n- rx: RX dump\n- tx: TX dump\n- rxtx: RX/TX dump\nRequired channels:\nNone.\nOptional channels:\n- rx (RX): UART receive line\n- tx (TX): UART transmit line\nOptions:\n- baudrate: Baud rate (default 115200)\n- data_bits: Data bits (5, 6, 7, 8, 9, default 8)\n- parity: Parity ('none', 'odd', 'even', 'zero', 'one', 'ignore', default 'none')\n- stop_bits: Stop bits (0.0, 0.5, 1.0, 1.5, default 1.0)\n- bit_order: Bit order ('lsb-first', 'msb-first', default 'lsb-first')\n- format: Data format ('ascii', 'dec', 'hex', 'oct', 'bin', default 'hex')\n- invert_rx: Invert RX ('yes', 'no', default 'no')\n- invert_tx: Invert TX ('yes', 'no', default 'no')\n- rx_packet_delim: RX packet delimiter (decimal) (default -1)\n- tx_packet_delim: TX packet delimiter (decimal) (default -1)\n- rx_packet_len: RX packet length (default -1)\n- tx_packet_len: TX packet length (default -1)\nDocumentation:\nUART (Universal Asynchronous Receiver Transmitter) is a simple serial\ncommunication protocol which allows two devices to talk to each other.\n\nThis decoder should work on all \"UART-like\" async protocols with one\nstart bit (0), 5-9 databits, an (optional) parity bit, and one or more\nstop bits (1), in this order.\n\nIt can be run on one signal line (RX or TX) only, or on two lines (RX + TX).\n\nThere are various standards for the physical layer specification of the\nsignals, including RS232, (TTL) UART, RS485, and others. However, the logic\nlevel of the respective pins is only relevant when acquiring the data via\na logic analyzer (you have to select the correct logic analyzer and/or\nthe correct place where to probe). Once the data is in digital form and\nmatches the \"UART\" description above, this protocol decoder can work with\nit though, no matter whether the source was on TTL UART levels, or RS232,\nor others.\n\n",
  "-P spi --show":
    "ID: spi\nName: SPI\nLong name: Serial Peripheral Interface\nDescription: Full-duplex, synchronous, serial bus.\nLicense: gplv2+\nPossible decoder input IDs:\n- logic\nPossible decoder output IDs:\n- spi\nDecoder tags:\nAnnotation classes:\n- miso-data: MISO data\n- mosi-data: MOSI data\n- miso-bits: MISO bits\n- mosi-bits: MOSI bits\n- warnings: Human-readable warnings\n- miso-transfer: MISO transfer\n- mosi-transfer: MOSI transfer\nAnnotation rows:\n- miso-bits (MISO bits): miso-bits\n- miso-data (MISO data): miso-data\n- miso-transfer (MISO transfer): miso-transfer\n- mosi-bits (MOSI bits): mosi-bits\n- mosi-data (MOSI data): mosi-data\n- mosi-transfer (MOSI transfer): mosi-transfer\n- other (Other): warnings\nBinary classes:\n- miso: MISO\n- mosi: MOSI\nRequired channels:\n- clk (CLK): Clock\nOptional channels:\n- miso (MISO): Master in, slave out\n- mosi (MOSI): Master out, slave in\n- cs (CS#): Chip-select\nOptions:\n- cs_polarity: CS# polarity ('active-low', 'active-high', default 'active-low')\n- cpol: Clock polarity (0, 1, default 0)\n- cpha: Clock phase (0, 1, default 0)\n- bitorder: Bit order ('msb-first', 'lsb-first', default 'msb-first')\n- wordsize: Word size (default 8)\nDocumentation:\nThe SPI (Serial Peripheral Interface) protocol decoder supports synchronous\nSPI(-like) protocols with a clock line, a MISO and MOSI line for data\ntransfer in two directions, and an optional CS# pin.\n\nEither MISO or MOSI (but not both) can be optional.\n\nIf CS# is supplied, data is only decoded when CS# is asserted (clock\ntransitions where CS# is not asserted are ignored). If CS# is not supplied,\ndata is decoded on every clock transition (depending on SPI mode).\n\n",
  "-P uart:rx=UART_TX:baudrate=115200 -A uart=rx-data":
    "209-279 uart-1: 48\n296-366 uart-1: 65\n383-453 uart-1: 6C\n470-540 uart-1: 6C\n557-627 uart-1: 6F\n644-714 uart-1: 20\n730-800 uart-1: 52\n817-887 uart-1: 45\n904-974 uart-1: 41\n991-1061 uart-1: 2B\n1078-1148 uart-1: 0D\n1164-1234 uart-1: 0A\n",
  "-P uart:rx=UART_TX:baudrate=115200 -A uart=rx-warnings": "",
  "-P uart:rx=UART_TX:baudrate=115200":
    "200-209 uart-1: Start bit\n209-218 uart-1: 0\n218-227 uart-1: 0\n226-235 uart-1: 0\n235-244 uart-1: 1\n244-253 uart-1: 0\n252-261 uart-1: 0\n261-270 uart-1: 1\n270-279 uart-1: 0\n209-279 uart-1: 48\n278-287 uart-1: Stop bit\n287-296 uart-1: Start bit\n296-305 uart-1: 1\n305-314 uart-1: 0\n313-322 uart-1: 1\n322-331 uart-1: 0\n331-340 uart-1: 0\n339-348 uart-1: 1\n348-357 uart-1: 1\n357-366 uart-1: 0\n296-366 uart-1: 65\n365-374 uart-1: Stop bit\n374-383 uart-1: Start bit\n383-392 uart-1: 0\n392-401 uart-1: 0\n400-409 uart-1: 1\n409-418 uart-1: 1\n418-427 uart-1: 0\n426-435 uart-1: 1\n435-444 uart-1: 1\n444-453 uart-1: 0\n383-453 uart-1: 6C\n452-461 uart-1: Stop bit\n461-470 uart-1: Start bit\n470-479 uart-1: 0\n479-488 uart-1: 0\n487-496 uart-1: 1\n496-505 uart-1: 1\n505-514 uart-1: 0\n513-522 uart-1: 1\n522-531 uart-1: 1\n531-540 uart-1: 0\n470-540 uart-1: 6C\n539-548 uart-1: Stop bit\n548-557 uart-1: Start bit\n557-566 uart-1: 1\n566-575 uart-1: 1\n574-583 uart-1: 1\n583-592 uart-1: 1\n592-601 uart-1: 0\n600-609 uart-1: 1\n609-618 uart-1: 1\n618-627 uart-1: 0\n557-627 uart-1: 6F\n626-635 uart-1: Stop bit\n635-644 uart-1: Start bit\n644-653 uart-1: 0\n653-662 uart-1: 0\n661-670 uart-1: 0\n670-679 uart-1: 0\n679-688 uart-1: 0\n687-696 uart-1: 1\n696-705 uart-1: 0\n705-714 uart-1: 0\n644-714 uart-1: 20\n713-722 uart-1: Stop bit\n721-730 uart-1: Start bit\n730-739 uart-1: 0\n739-748 uart-1: 1\n747-756 uart-1: 0\n756-765 uart-1: 0\n765-774 uart-1: 1\n773-782 uart-1: 0\n782-791 uart-1: 1\n791-800 uart-1: 0\n730-800 uart-1: 52\n799-808 uart-1: Stop bit\n808-817 uart-1: Start bit\n817-826 uart-1: 1\n826-835 uart-1: 0\n834-843 uart-1: 1\n843-852 uart-1: 0\n852-861 uart-1: 0\n860-869 uart-1: 0\n869-878 uart-1: 1\n878-887 uart-1: 0\n817-887 uart-1: 45\n886-895 uart-1: Stop bit\n895-904 uart-1: Start bit\n904-913 uart-1: 1\n913-922 uart-1: 0\n921-930 uart-1: 0\n930-939 uart-1: 0\n939-948 uart-1: 0\n947-956 uart-1: 0\n956-965 uart-1: 1\n965-974 uart-1: 0\n904-974 uart-1: 41\n973-982 uart-1: Stop bit\n982-991 uart-1: Start bit\n991-1000 uart-1: 1\n1000-1009 uart-1: 1\n1008-1017 uart-1: 0\n1017-1026 uart-1: 1\n1026-1035 uart-1: 0\n1034-1043 uart-1: 1\n1043-1052 uart-1: 0\n1052-1061 uart-1: 0\n991-1061 uart-1: 2B\n1060-1069 uart-1: Stop bit\n1069-1078 uart-1: Start bit\n1078-1087 uart-1: 1\n1087-1096 uart-1: 0\n1095-1104 uart-1: 1\n1104-1113 uart-1: 1\n1113-1122 uart-1: 0\n1121-1130 uart-1: 0\n1130-1139 uart-1: 0\n1139-1148 uart-1: 0\n1078-1148 uart-1: 0D\n1147-1156 uart-1: Stop bit\n1155-1164 uart-1: Start bit\n1164-1173 uart-1: 0\n1173-1182 uart-1: 1\n1181-1190 uart-1: 0\n1190-1199 uart-1: 1\n1199-1208 uart-1: 0\n1207-1216 uart-1: 0\n1216-1225 uart-1: 0\n1225-1234 uart-1: 0\n1164-1234 uart-1: 0A\n1233-1242 uart-1: Stop bit\n",
  "-P spi:clk=CLK:mosi=MOSI:cs=CS -A spi=mosi-data":
    "1357-1437 spi-1: 9F\n1437-1517 spi-1: EF\n1517-1597 spi-1: 40\n1597-1677 spi-1: 18\n",
};

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(0);
};

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--version") {
  process.stdout.write(
    scenario === "version-drift"
      ? RECORDED["--version"].replace("sigrok-cli 0.7.2", "sigrok-cli 0.8.0")
      : RECORDED["--version"],
  );
  process.exit(0);
}
if (scenario === "hang") setInterval(() => {}, 1_000);
else if (args.length === 3 && args[0] === "-P" && args[2] === "--show") {
  const output = RECORDED[`-P ${args[1]} --show`];
  if (output === undefined)
    fail(
      `srd: ModuleNotFoundError: Failed to load decoder ${args[1]}: import by name failed: No module named '${args[1]}'`,
    );
  process.stdout.write(output);
} else {
  if (args[0] !== "-i" || args.at(-1) !== "--protocol-decoder-samplenum")
    fail(`unmodeled arguments: ${args.join(" ")}`);
  const digest = createHash("sha256")
    .update(readFileSync(args[1] ?? ""))
    .digest("hex");
  if (digest !== FIXTURE_SHA256) fail("cli: unmodeled capture");
  if (scenario === "decoder-error")
    fail("srd: Required channel 'clk' (index 0) was not specified.");
  const output = RECORDED[args.slice(2, -1).join(" ")];
  if (output === undefined) fail(`unmodeled arguments: ${args.join(" ")}`);
  process.stdout.write(output);
}
