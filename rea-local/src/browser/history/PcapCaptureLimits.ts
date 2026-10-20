export const MAX_OUTPUT_RESERVE = 1024;
export const MAX_PCAPNG_INTERFACES = 65_536;
export const MAX_IPV6_EXTENSION_HEADERS = 16;
export const PCAPNG_SECTION_HEADER_MAGIC = Buffer.from([
  0x0a, 0x0d, 0x0d, 0x0a,
]);

export const LIMITATIONS = [
  "Packet records preserve exact captured frame bytes, source byte ranges and producer ordinals. Link/IP/TCP/UDP headers are decoded when supported; IP fragments and TCP streams are not reassembled and TLS is not decrypted.",
  "Application metadata covers only messages that begin in the packet: HTTP/1.x request and status heads, cleartext TLS ClientHello/ServerHello fields, and DNS messages on ports 53/5353. Data continuing in later segments is not decoded. HTTP credential header values and URL userinfo are removed, and frames carrying them do not retain their bytes.",
  "Flow keys group packets by a normalized transport five-tuple only; they do not distinguish repeated sessions that reuse the same tuple. Unsupported link types and incomplete headers remain opaque, and runtime/application attribution is unknown.",
];
