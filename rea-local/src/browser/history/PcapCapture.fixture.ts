/** One Ethernet/IPv4 TCP (PSH|ACK) or UDP frame from 192.0.2.1 to 198.51.100.2. */
export const ethernetIpv4Frame = (
  protocol: "tcp" | "udp",
  payload: Buffer = Buffer.from("payload"),
  ports: {
    readonly source: number;
    readonly destination: number;
  } = protocol === "tcp"
    ? { source: 12_345, destination: 443 }
    : { source: 53_000, destination: 53 },
): Buffer => {
  const transportLength = protocol === "tcp" ? 20 : 8;
  const frame = Buffer.alloc(14 + 20 + transportLength + payload.length);
  Buffer.from("00112233445566778899aabb0800", "hex").copy(frame, 0);
  const ipOffset = 14;
  frame[ipOffset] = 0x45;
  frame.writeUInt16BE(20 + transportLength + payload.length, ipOffset + 2);
  frame.writeUInt16BE(0x1234, ipOffset + 4);
  frame[ipOffset + 8] = 64;
  frame[ipOffset + 9] = protocol === "tcp" ? 6 : 17;
  Buffer.from([192, 0, 2, 1]).copy(frame, ipOffset + 12);
  Buffer.from([198, 51, 100, 2]).copy(frame, ipOffset + 16);
  const transportOffset = ipOffset + 20;
  frame.writeUInt16BE(ports.source, transportOffset);
  frame.writeUInt16BE(ports.destination, transportOffset + 2);
  if (protocol === "tcp") {
    frame.writeUInt32BE(77, transportOffset + 4);
    frame.writeUInt32BE(88, transportOffset + 8);
    frame[transportOffset + 12] = 0x50;
    frame[transportOffset + 13] = 0x18;
    frame.writeUInt16BE(8192, transportOffset + 14);
  } else {
    frame.writeUInt16BE(8 + payload.length, transportOffset + 4);
    frame.writeUInt16BE(0, transportOffset + 6);
  }
  payload.copy(frame, transportOffset + transportLength);
  return frame;
};

/** Classic PCAP 2.4 container with one record per frame. */
export const classicPcap = (
  frames: readonly Buffer[],
  endian: "little" | "big" = "little",
  nanoseconds = false,
): Buffer => {
  const header = Buffer.alloc(24);
  const magic =
    endian === "little"
      ? nanoseconds
        ? "4d3cb2a1"
        : "d4c3b2a1"
      : nanoseconds
        ? "a1b23c4d"
        : "a1b2c3d4";
  Buffer.from(magic, "hex").copy(header, 0);
  const writeU16 = (value: number, offset: number): void => {
    if (endian === "little") header.writeUInt16LE(value, offset);
    else header.writeUInt16BE(value, offset);
  };
  const writeI32 = (value: number, offset: number): void => {
    if (endian === "little") header.writeInt32LE(value, offset);
    else header.writeInt32BE(value, offset);
  };
  const writeHeaderU32 = (value: number, offset: number): void => {
    if (endian === "little") header.writeUInt32LE(value, offset);
    else header.writeUInt32BE(value, offset);
  };
  writeU16(2, 4);
  writeU16(4, 6);
  writeI32(0, 8);
  writeHeaderU32(0, 12);
  writeHeaderU32(65_535, 16);
  writeHeaderU32(1, 20);
  const records = frames.map((frame, index) => {
    const packetHeader = Buffer.alloc(16);
    const writeRecordU32 = (value: number, offset: number): void => {
      if (endian === "little") packetHeader.writeUInt32LE(value, offset);
      else packetHeader.writeUInt32BE(value, offset);
    };
    writeRecordU32(1_700_000_000 + index, 0);
    writeRecordU32(nanoseconds ? 123 : 123_456, 4);
    writeRecordU32(frame.length, 8);
    writeRecordU32(frame.length, 12);
    return Buffer.concat([packetHeader, frame]);
  });
  return Buffer.concat([header, ...records]);
};
