# Historical web network captures

Use `inspect_web_network_capture` / `inspect-web-network-capture` to inspect
retained producer evidence. This is an offline operation: recorded URLs are
never fetched, and no browser or proxy listener is started.

```sh
rea inspect-web-network-capture /absolute/session.har har --json
rea inspect-web-network-capture /absolute/session.har har --record 2 --record 0 --json
rea inspect-web-network-capture /absolute/session.pcap pcap --record 0 --json
rea inspect-web-network-capture /absolute/session.pcapng pcapng --record 0 --json
```

```json
{
  "name": "inspect_web_network_capture",
  "arguments": {
    "capture_path": "/absolute/session.har",
    "format": "har",
    "record_ordinals": [2, 0]
  }
}
```

Omit ordinals to return every record. Explicit selection preserves caller order
and original zero-based producer ordinals; duplicate or out-of-range selections
are input errors. Every HAR entry is schema-validated before success. For
PCAP/PCAPNG, every packet-record length and container block boundary/trailer is
checked; only selected frames receive link/IP/transport parsing. Selection does
not hide malformed HAR entries or packet/block framing elsewhere. HAR and
PCAP/PCAPNG retain only requested record objects in the owned decoder; native
mitmproxy still completes its full decode before the shared selector runs.
Selection reduces retained/output data and packet-header parsing work, but not
the complete artifact read or structural validation.

## Formats and upstream profiles

HAR uses unchanged `har-schema@2.0.0` draft-06 schemas, `ajv@8.20.0`,
`ajv-formats@3.0.1`, `jsonc-parser@3.3.1` JSON visitor, and
`lossless-json@4.3.1` numeric representations, pinned in the npm lockfile.
Only the HAR 1.2 profile is supported. Unknown extensions remain reported
evidence for retained records/container metadata. A duplicate-aware JSON
visitor walks the complete file without building a document-sized syntax tree;
it checks duplicate keys (including equal values and escaped spellings), JSON
syntax and the depth budget before any result is returned. Each unselected entry is
projected to the pinned schema's fields, validated and discarded one at a time;
only requested entries are retained as full output records. Canonical base64 is
checked in every entry, including unselected records. Prototype-named members
such as `__proto__` in retained evidence are preserved as ordinary own JSON
members without prototype mutation. Original capture files remain unchanged.
The observed mitmproxy 12.2.3 `SaveHar` profile can emit `postData.text: null`
for a missing request body. REA+ preserves that reported null, omitting the
optional field only from its validation copy for this exact producer profile;
it does not invent an empty string or body bytes.

Native mitmproxy decoding requires a caller-supplied **mitmdump 12.2.3 on
Linux**. Set its absolute executable path:

```sh
REA_MITMDUMP_COMMAND=/absolute/mitmdump rea inspect-web-network-capture /absolute/session.mitm mitmproxy --json
```

REA+ does not install mitmproxy. Its owned process uses a private configuration
directory, `--no-server`, and the unchanged upstream `mitmproxy.io.tnetstring`
decoder. It does not run `FlowReader` migrations or convert native states to
HAR. Raw IDs, state versions, flow types, backup states and unknown extensions
are preserved without synthesizing connections, timestamps or content. The
tested upstream source is tag `v12.2.3`, commit
`6c09d56e4c29a92f5ad01b03199977584b8ea14f`; other native tool versions return
an explicit unsupported-profile diagnostic. Non-Linux native decoding is not
supported by this adapter.

Classic PCAP 2.4 (little/big endian, microsecond/nanosecond timestamps) and
PCAPNG 1.0 (little/big endian sections) are decoded by REA+'s bounded offline
packet parser; no external packet-analysis program is installed or invoked.
Packet capture records preserve producer ordinals, packet-block kind, byte
ranges, packet-data offsets, PCAPNG section/interface indices and exact captured
frame bytes. Ethernet (including supported VLAN tags), raw-IP and Linux cooked
v1/v2 link types receive bounded link/IP/TCP/UDP/ICMP metadata parsing;
other link types and incomplete headers remain opaque. PCAPNG section/interface
blocks and packet-block lengths/trailers are checked; non-packet, custom and
unknown block contents are not retained or interpreted. PCAPNG permits at most
65,536 interfaces per section. A normalized transport five-tuple groups TCP/UDP
packets when endpoints are present; it is not a connection-lifecycle ID and
repeated sessions can reuse the same key. IP fragments and TCP streams are not
reassembled and TLS is not decrypted. These records do not establish browser,
process, application or runtime attribution.

### Application metadata

Each packet record also has an `application` object (or `null`) for messages
that begin in that packet. Nothing is reassembled, so data continuing in later
segments is not decoded.

- **HTTP/1.x**: a request or status line at the start of a TCP payload. The
  record reports the method and target or status and reason, ordered headers
  with byte-exact latin1 values, whether the head ended in this segment, any
  cut-off last line, and body bytes present in the segment.
- **TLS**: a cleartext ClientHello or ServerHello at the start of a TCP
  payload. The record reports record and legacy versions, server names (SNI),
  ALPN protocols, supported versions, the extension type list, the
  ServerHello cipher suite, and `complete: false` when the hello continues in
  a later segment.
- **DNS**: complete messages on UDP or TCP ports 53 and 5353. The record
  reports the header flags and counts, questions, and answer, authority and
  additional records with decoded A, AAAA, CNAME, NS, PTR, MX and TXT data
  (other types keep bounded hex). Names use RFC 1035 presentation escapes.
  Compression loops, truncation and trailing bytes are reported in
  `decode_status`; at most 64 records per section are listed.

`Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` values are
removed, including a credential line cut at the segment end, and URL userinfo
is stripped from request targets and `Location`, `Referer` and `Origin`
values. Each removal is listed in `redactions` as `transport-credential`.
Because the frame bytes contain the same credential, a frame with any such
removal keeps neither its bytes nor their digest (`/frame/data` is redacted).
The decoder identity is `rea-offline-pcap` version `1.1.0`.

Tests use payloads recorded on loopback with tcpdump 4.99.4 from DiG 9.18,
curl 8.5.0, Python `http.server` and OpenSSL 3.0.13; HTTP/2, QUIC, DNS over
HTTPS and encrypted TLS records are not decoded.

## Reading the evidence

- `artifact` identifies the caller-selected file and stable snapshot digest.
- `records` preserve producer order/ordinals and original JSON pointers or byte
  ranges. No live browser transaction or scenario IDs are invented.
- `reported` preserves retained HAR/mitmproxy producer fields. HAR container
  metadata is returned separately, with `log.entries` replaced by `null` and
  `records_pointer` identifying the collection; this is not a reconstructed
  HAR file. PCAP/PCAPNG `reported` contains bounded decoded link/IP/transport
  metadata and source frame offsets; `records_pointer` is `null`.
- `numeric_literals` preserve HAR number lexemes and native integer/float
  representations, including unsafe integers and non-finite native floats.
  Packet metadata preserves exact binary integer literals as sidecars. Values
  that cannot be safely represented as JSON numbers are `null` in the reported
  view. Unsafe standard HAR numeric fields fail schema validation; unsafe
  extension numbers remain available through their sidecars.
- `binary_fields` retain exact exposed bytes, base64 and SHA-256 independently
  of declared sizes. This includes captured packet-frame bytes for PCAP/PCAPNG
  and producer bytes for native mitmproxy. Valid HAR
  `content.encoding: "base64"` is decoded exactly; producer-decoded Unicode
  text, missing text and unknown encodings do not establish original HAR body
  bytes. Post-data parameters do not reconstruct a multipart body. Native byte
  fields also have an exact UTF-8 display view when valid; binary sidecars
  establish their actual representation. Native missing content and empty
  content remain distinct.
- `redactions` identify known transport authentication exclusions for HAR and
  mitmproxy plus explicitly sensitive text/byte/numeric/coordinate exclusions.
  Packet payloads are not interpreted as HTTP headers or cookies; PCAP raw
  bytes are excluded only when they match an explicit sensitive declaration.
  Redacted byte fields retain neither original bytes nor their digest. Unknown
  extension names and token-looking query parameters do not establish
  sensitivity.

Mark sensitive literal string/UTF-8 byte values with MCP `sensitive_values`, or
repeat CLI `--sensitive-value`. These declarations are never persisted in
Evidence parameters; the count is retained. Explicit text/UTF-8 byte matches
exclude the entire field with a reported `null` rather than substitute a text
marker or rewrite payload bytes. This prevents replacement markers from
reintroducing declared literals. The file digest identifies the original artifact
unless it matches an explicit declaration; in that case `artifact.sha256` and
Evidence `subject` are null with an explanation. A sensitive property name excludes that
entire property and its sidecars; a `scope: "property-name"` redaction points
to its actual parent. No substitute property name or child pointer is invented.
Omitted HAR subtrees are still validated, including canonical base64.
Explicitly sensitive artifact paths are empty in Evidence and omitted from
locations, while the original SHA-256 and size remain available unless the
digest itself is explicitly excluded. Failure messages, diagnostics and cleanup
resources follow the same explicit declarations without changing error types;
sensitive issue pointers identify a real ancestor instead of a fabricated
coordinate. HAR and native mitmproxy exclude known authentication headers,
cookies and transport URL userinfo structurally, including native backups; the
packet parser does not claim to identify application-layer credentials.

Generated free-text limitations follow the same literal declarations, including
global, per-record and Evidence explanations added during projection. Contract
field names, typed discriminators and exact decoder identities keep their
canonical meanings; declarations do not rename formats or providers.

Historical evidence does not prove runtime attribution, execution or deployment
authenticity. Mitmproxy messages are upstream-assembled messages, not recovered
wire fragments. Native dictionary duplicate keys have the unchanged upstream
decoder's last-value semantics; this adapter does not claim to recover discarded
duplicates or the original numeric spelling of parsed native floats.

## Resource and lifecycle boundaries

Complete evidence has a 32 MiB input and 96 MiB decoder-reply budget; HAR also
has a 64-level JSON nesting budget, and PCAPNG limits each section to 65,536
interfaces. Exceeding a budget returns no partial success. Oversized selected
captures return an input error identifying `capture_path` and the applicable
budget; owned reply/output failures remain output or provider errors.

HAR and PCAP/PCAPNG run in an owned 192 MiB Node old-generation heap with one
V8 worker. Native mitmproxy decoding applies Linux limits of 768 MiB address
space, 30 seconds CPU and 96 MiB file output. All owned commands have a
30-second wall deadline and independently supervised process cleanup. Owned
decoder diagnostics retain at most 1 MiB across stdout and stderr; the collector
drops overflow as it arrives, reports the limit failure and verifies cleanup.
Heap limits alone do not establish aggregate RSS limits.

When REA+ runs on Bun, the JavaScript decoders run on Bun, which ignores V8 heap
flags; their limitations and resource failures then omit the heap sizes. On
Windows, each owned Job Object instead limits committed memory to 704 MiB, the
192 MiB budget plus a 512 MiB reserve for Bun itself. The limitations state
that limit, and reaching it returns `resource_constraint` with
`process_memory_limit_bytes`, whatever exit status Bun reports.

Observed decoder memory exhaustion returns `resource_constraint`, with the
selected capture, applicable limits and retained process diagnostics. The HAR
and PCAP/PCAPNG old-generation heaps are fixed; inherited `NODE_OPTIONS` cannot
raise them. Selection reduces retained HAR/packet records, reply size and
unselected packet-header parsing, but does not skip full-file reads, HAR schema
validation or packet/block structural checks. Native mitmproxy selection still
follows its complete native decode. Use a smaller capture
exported by its producer or another decoder with sufficient capacity, retaining
the original for provenance. Subsets do not establish complete-capture
coverage. Repeating the same workload or running provider health diagnostics
does not resolve the heap constraint.

Stable regular-file reads reject symlinks, replacement and concurrent changes.
Private snapshots, declarations and tool configuration are removed before the
result returns. Cleanup uncertainty retains the selected capture, resource and
original failure information. The original capture is never changed.

## Excluded coordinates and read failures

Explicitly marked values also exclude matching source coordinates and their sidecars. A hidden record coordinate is reported as `location.kind: "unknown"`; REA+ does not invent a replacement pointer. Original record ordinals and artifact digests remain available.

Host filesystem read denials return `code: "access_denied"`, `category: "unavailable"`, the actual `EACCES`/`EPERM` code and read-access guidance. Missing files remain input failures. Cleanup failures retain the prior structured error, including its input constraints or provider diagnostics, with explicitly marked text excluded.

An observed replacement or in-place change during stable artifact acquisition
returns `code: "artifact_changed"`, `category: "integrity_mismatch"` and
`retryable: true`, retaining the selected path and reader's reason. Wait until
the capture file is stable before retrying. No unstable snapshot is decoded.
Command cleanup failures retain the original status and both diagnostic streams;
the decoder's ownership preparation receives the same cancellation signal.

MCP advertises the same strict named input contract used by the application. Historical inspection delegates argument validation to that shared application boundary so accepted explicit-sensitive declarations also cover invalid argument names and other correction details. The SDK receives raw arguments through its Standard Schema interface; malformed inputs still fail before decoder or filesystem effects and return the normal structured REA+ error. Protocol-envelope validation remains owned by MCP.
