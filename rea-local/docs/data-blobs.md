# Data blobs

`inspect_data_blob` / `inspect-data-blob` decodes structured binary data
when you have no schema for it: save games, caches, settings blobs, packet
payloads and Minecraft worlds. It reads:

- Protocol Buffers without a `.proto`, the way `protoc --decode_raw` does;
- MessagePack, CBOR and BSON;
- Java NBT (big-endian) and Bedrock NBT (little-endian, with or without
  `level.dat`'s 8-byte header);
- JSON;
- Minecraft Anvil region files (`.mca`, `.mcr`) and the NBT of any chunk.

Before decoding, it removes the wrapping layers it can recognise: base64,
hex, gzip, zlib, zstd and LZ4 frames. Raw deflate and Brotli carry no
signature, so you name them in `layers`. If nothing decodes the payload,
the result falls back to its printable strings.

```sh
rea inspect-data-blob ~/Games/save/slot1.sav --json
rea inspect-data-blob slot1.sav --view strings --query gold --json
rea inspect-data-blob packet.bin --range_offset 12 --range_length 340 --format protobuf --json
rea inspect-data-blob settings.dat --layers base64,deflate --json
rea inspect-data-blob world/region/r.0.0.mca --json
rea inspect-data-blob world/region/r.0.0.mca --region_chunk 33 --node '$.Level.Sections[2]' --max_depth 1 --json
```

```json
{
  "name": "inspect_data_blob",
  "arguments": {
    "path": "/games/save/slot1.sav",
    "node": "$.inventory",
    "max_depth": 2
  }
}
```

## What the result contains

- `file`: path, SHA-256 and size. `range`: the bytes taken from the file.
- `layers`: each layer removed, with its input and output size.
- `payload`: size and SHA-256 of the bytes that were decoded.
- `format`: the decoder used, whether you forced it, and the region chunk.
- `candidates`: every format tried. Each has whether it read the whole
  payload, a plausibility score, and the error if it failed. With
  `format: "auto"`, the most plausible full decoding wins. JSON and NBT
  rank above BSON, which ranks above MessagePack, CBOR and protobuf. Text
  and opaque byte leaves lower a score.
- `summary`: node count, depth and text leaves.
- `page` and one view, filtered by `node`, `max_depth` and `query`:
  - `tree` (default): one row per node, depth first. Each row has a `path`
    (`$`, `$.player`, `$.items[1].name`, `$["key with spaces"]`), the key,
    type, value, byte `offset` and `length`, and a child count.
  - `strings`: the text leaves with their paths. For an undecoded payload,
    the printable runs of six or more characters, at `@offset`.

### Protobuf without a schema

A protobuf message stores field numbers and wire types, not names or
declared types. So every value carries its other readings in
`alternatives`:

- a varint: `int64`, `sint64` (zigzag) and `bool`;
- a fixed32 or fixed64: the signed integer, the float or double, and hex;
- opaque bytes: `packed_varints` when they read as a packed list.

A length-delimited field becomes a nested message whenever its bytes parse
as one, and text when they are UTF-8. Both rules are protoc's. Repeated
fields get indexes (`$.9[0]`, `$.9[1]`), and groups are kept.

### Region files

A region file lists its 1,024 chunk slots. Each present chunk shows its
coordinates, compression, size and timestamp, or why it cannot be read: no
data, sectors outside the file, or an unknown compression type.
`region_chunk` (z × 32 + x) decodes one chunk's NBT. The chunk can be
stored with gzip (1), zlib (2), no compression (3) or LZ4 (4), the type
numbers Minecraft uses today. Some tools store a chunk length a byte short,
which cuts off the end of the compressed stream. Such a stream is read on to
the end of the chunk's own sectors.

## Boundaries

- Decoding without a schema is a guess. Short or random payloads can decode
  as more than one format. Check `candidates`, or name the `format`.
- Encryption, XOR masks, custom framing and game-specific compression are
  not undone. Use `range_offset` and `range_length` to skip a header you
  have identified.
- JSON nodes carry no byte offsets of their own; they span the whole text.
- External `.mcc` chunks are not read. NBT nested deeper than 512 levels is
  refused, as Minecraft does.
- At most 8 layers are removed, and no layer may expand past 1 GiB.
- Files over 512 MiB are refused.

## Verification

`tests/boundary/providers/blob/dataBlob.test.ts` builds the same small save
in every format, with encoders written from each specification:

- protobuf's wire format;
- MessagePack and CBOR (RFC 8949);
- BSON 1.1;
- Java and Bedrock NBT;
- an Anvil region file;
- an uncompressed LZ4 frame.

The tests check each tree with its offsets and protobuf readings. They also
check automatic and named layers, byte ranges, subtrees, queries, region
chunks, the strings fallback, and the refusal of selections that do not
exist.

Four lanes check the decoders against independent tools:

- `REA_VERIFY_PROTOC`: 300 random messages, with nested messages, groups,
  packed fields, text and opaque bytes, plus a descriptor set and a message
  written by protoc itself. Each must print exactly as
  `protoc --decode_raw` prints it.
- `REA_VERIFY_BLOB_PYTHON`: a Python with the `msgpack`, `cbor2` and
  `bson` packages writes 200 random nested values in each format. The tree
  must equal what each library decodes.
- `REA_VERIFY_LZ4_BIN` and `REA_VERIFY_ZSTD_BIN`: a 75 KiB payload
  compressed by the `lz4` tool (linked 64 KiB blocks, and high compression)
  and the `zstd` tool must come back byte for byte.
- `REA_VERIFY_NBT_DIR`: every `.nbt`, `.dat`, `.mca` and `.mcr` file in a
  folder must decode, and `bigtest.nbt` must list the values its
  specification gives. Every chunk a region header lists as readable must
  decode as NBT. Files named `invalid_*` or `max_depth*` must not decode as
  NBT.

All four lanes passed with protoc 3.21.12, Ubuntu's `python3-msgpack`,
`python3-cbor2` and `python3-bson` (pymongo's `bson`), lz4 1.9.4 and zstd
1.5.5. The NBT folder held the test files of twoolie/NBT and Querz/NBT:

- twoolie's `regiontest.mca` is damaged on purpose, and its tests list
  which chunks can be read. REA+ agrees on every chunk but two. That file
  uses type 0 for uncompressed and 3 as unknown, the reverse of what
  Minecraft defines now.
- Querz's `r.2.2.mca` stores every chunk length a byte short. Its chunks
  decode through the rule above.
