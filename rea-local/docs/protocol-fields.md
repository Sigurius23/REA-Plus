# Protocol field inference

`infer_protocol_fields` / `infer-protocol-fields` infers the message formats
of an undocumented protocol, such as a game's netcode or a device's control
channel. It works from a packet capture or a file of hex messages, the way
Netzob and similar tools do, and sends nothing.

1. Messages are collected:
   - UDP datagrams are messages as they are.
   - TCP streams are reassembled by sequence number, split where data is
     missing, then framed. A length prefix wins when it tiles every stream
     exactly and starts messages where the sender's segments start.
     Otherwise text streams split at line breaks and binary streams at NULs.
     Failing both, each segment is a message.
   - A text file has one message per line in hex.
2. Messages are grouped into formats. The grouping uses one or two type
   bytes near the start, the direction (requests and responses), or for
   text, the first word. Each candidate grouping is scored by how much fixed
   structure it explains.
3. Each format's fixed header is broken into fields, most specific first:
   - the type bytes;
   - length fields, with how the value relates to the message's length;
   - counters, judged over each flow in capture order;
   - checksums, naming the algorithm and the bytes they cover;
   - timestamps (seconds, milliseconds or microseconds since 1970, or NTP
     seconds since 1900) within a day of the capture's clock;
   - constants;
   - text;
   - 32-bit floats;
   - small enums, unique ids and plain bytes;
   - the variable part after the header.

```sh
rea infer-protocol-fields ~/captures/game.pcapng --transport udp --port 7777 --json
rea infer-protocol-fields game.pcapng --port 7777 --view fields --format 2 --json
rea infer-protocol-fields game.pcapng --port 7777 --view messages --format 2 --json
rea infer-protocol-fields ~/notes/packets.txt --view fields --json
```

```json
{
  "name": "infer_protocol_fields",
  "arguments": {
    "path": "/captures/game.pcapng",
    "port": 7777,
    "view": "fields"
  }
}
```

For example, on a game protocol it reports:

- a constant `GAME`;
- a type byte;
- a `u32le` counter that increments by 1;
- a `u16le` length (message length − 19);
- a `u32le` CRC-32 of bytes 19 to the end;
- a `u32le` timestamp in seconds since 1970;
- per format, the payload: three floats and an enum, text, or an 8-byte
  id.

## What the result contains

- `source`: PCAP, PCAPNG or hex lines; frames read; messages analysed.
- `framing`: datagrams, lines, segments, a delimiter, or a length prefix
  with its offset, width, byte order and adjustment (message length = value
  - adjust).
- `inference`: whether the messages are text, and the byte order the
  unambiguous fields use.
- `page` and one view:
  - `formats`: id, type value and its position, direction, message count
    and lengths.
  - `fields`: per format, each field's offset, length, kind, encoding,
    detail and sample values. A trailer in messages of different lengths
    counts from the end.
  - `messages`: each message's format, flow, direction, time, length and
    first 64 bytes.
  - `flows`: the flows the messages came from.

## Boundaries

Every field is a hypothesis. Test it by changing the value in a replayed
or edited message.

- Fields are found at fixed offsets within a format. A field after a
  variable-length one is not found.
- Adjacent fields that never change merge into one constant run, such as
  DNS flags and counts in a capture of similar queries.
- A format seen in only a few messages yields little.
- When a field's top byte is always zero, its width and byte order are
  ambiguous. The capture's unambiguous fields settle the byte order (network
  order when there are none). Counters are read 32 bits wide while their
  upper half is zero, lengths 16 bits.
- Formats told apart by something other than a type field, direction or
  first word are analysed as one format.
- At most √n formats are kept, and at least 4: an id byte would otherwise
  make a format of each message.
- When UDP and TCP payloads are both in the selection, the tool asks for
  `transport` or `port` rather than mixing protocols.
- Encrypted or compressed payloads (TLS, QUIC, zlib) show no structure.
- Checksums are recognised among CRC-32, CRC-32C, Adler-32, CRC-16
  (CCITT-FALSE, XMODEM, MODBUS, ARC), Fletcher-16, the internet checksum,
  and 8- and 16-bit sums and XOR. DNP3's CRC is not among them.
- Only the first 5000 messages are analysed. Captures over 1 GiB are
  refused.

## Verification

`tests/boundary/providers/protocol/protocolFields.test.ts` writes classic
PCAP and PCAPNG captures byte by byte. A game protocol's three formats must
come back with every header field above and their payload fields. A
length-prefixed TCP stream must reassemble into its 40 messages, byte for
byte, despite:

- segments sent out of order or twice;
- a message split across segments;
- segments holding two messages.

The tests also cover line framing, hex lines, filters and refusals.

`tests/boundary/providers/protocol/protocolFieldsReal.test.ts` adds:

- `REA_VERIFY_PROTOCOL_SAMPLES`: Wireshark's sample captures. The tool must
  find:
  - the length framing of IEC 104 (a u8 after the start byte) and S7comm
    (TPKT's u16be total length);
  - TFTP's block counter;
  - NTP's transmit timestamp in every format;
  - DHCP's magic cookie inside a constant run.

  With `REA_VERIFY_TSHARK`, every type, length, counter, checksum and
  timestamp field must start where tshark's dissectors start a field:
  - TFTP: 99 of 99 checks;
  - NTP: 60 of 60;
  - DNS: 38 of 38;
  - CoAP: 164 of 328. Its 4-byte token counts in its low half, which is
    read as a counter two bytes into the field.

- `REA_VERIFY_SCAPY_PYTHON`: a scapy script writes captures of DNS,
  Modbus/TCP, a TFTP read, a length-prefixed stream, a line protocol and the
  game protocol. Expected results:
  - Modbus must frame by its u16be length (adjust 6), with the transaction
    counter, the protocol id constant, the length and the function code as
    the type;
  - the game protocol's header must come back as above;
  - with tshark, generated DNS and TFTP must score every check.

The lanes passed with tshark 4.2.2 and scapy 2.5.0 from Ubuntu's packages.
