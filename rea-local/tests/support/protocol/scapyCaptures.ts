/**
 * A Python script (scapy) that writes captures of protocols with known
 * layouts: DNS, Modbus/TCP with several requests per connection, a TFTP
 * read, a length-prefixed TCP stream, a line protocol, and a game protocol
 * with a sequence number, payload length, CRC-32 and timestamp.
 */
export const SCAPY_CAPTURES = String.raw`import random, struct, sys, warnings, zlib
warnings.filterwarnings("ignore")
from scapy.all import IP, UDP, TCP, Ether, Raw, DNS, DNSQR, DNSRR, wrpcap
out = sys.argv[1]
rng = random.Random(11)
def at(p, t): p.time = t; return p
# DNS: queries and answers
pk = []
t = 1760000000.0
for i in range(80):
    name = rng.choice(["example.com", "game.example.net", "cdn.assets.example.org", "a.b"])
    qid = rng.getrandbits(16)
    sport = 30000 + rng.randrange(2000)
    pk.append(at(Ether()/IP(src="10.0.0.5", dst="10.0.0.53")/UDP(sport=sport, dport=53)/DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=rng.choice(["A", "AAAA", "TXT"]))), t)); t += 0.01
    pk.append(at(Ether()/IP(src="10.0.0.53", dst="10.0.0.5")/UDP(sport=53, dport=sport)/DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=rng.randint(30, 3600), rdata="93.184.216.%d" % rng.randint(1, 250))), t)); t += 0.01
wrpcap(f"{out}/dns.pcap", pk)
# Modbus/TCP: several requests and responses per connection, sometimes two per segment
pk = []
for conn in range(4):
    sport = 50000 + conn
    seq_c, seq_s = 1000, 9000
    tid = rng.randrange(100)
    for i in range(30):
        tid += 1
        fc = rng.choice([3, 4, 6, 16])
        addr, count = rng.randrange(1000), rng.randint(1, 10)
        if fc in (3, 4): pdu, rpdu = struct.pack(">BHH", fc, addr, count), struct.pack(">BB", fc, count * 2) + bytes(rng.getrandbits(8) for _ in range(count * 2))
        elif fc == 6: pdu = rpdu = struct.pack(">BHH", fc, addr, rng.getrandbits(16))
        else:
            vals = bytes(rng.getrandbits(8) for _ in range(count * 2)); pdu, rpdu = struct.pack(">BHHB", fc, addr, count, count * 2) + vals, struct.pack(">BHH", fc, addr, count)
        req = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu
        rsp = struct.pack(">HHHB", tid, 0, len(rpdu) + 1, 1) + rpdu
        pk.append(at(Ether()/IP(src="10.0.1.2", dst="10.0.1.3")/TCP(sport=sport, dport=502, seq=seq_c, flags="PA")/Raw(req), t)); seq_c += len(req); t += 0.01
        pk.append(at(Ether()/IP(src="10.0.1.3", dst="10.0.1.2")/TCP(sport=502, dport=sport, seq=seq_s, flags="PA")/Raw(rsp), t)); seq_s += len(rsp); t += 0.01
wrpcap(f"{out}/modbus.pcap", pk)
# TFTP read: RRQ, DATA blocks, ACKs
pk = []
for transfer in range(3):
    cport, sport = 40000 + transfer, 60000 + transfer
    pk.append(at(Ether()/IP(src="10.0.2.2", dst="10.0.2.3")/UDP(sport=cport, dport=69)/Raw(b"\x00\x01" + b"firmware%d.bin\x00octet\x00" % transfer), t)); t += 0.01
    for block in range(1, 25):
        data = bytes(rng.getrandbits(8) for _ in range(512 if block < 24 else rng.randrange(1, 511)))
        pk.append(at(Ether()/IP(src="10.0.2.3", dst="10.0.2.2")/UDP(sport=sport, dport=cport)/Raw(struct.pack(">HH", 3, block) + data), t)); t += 0.01
        pk.append(at(Ether()/IP(src="10.0.2.2", dst="10.0.2.3")/UDP(sport=cport, dport=sport)/Raw(struct.pack(">HH", 4, block)), t)); t += 0.01
wrpcap(f"{out}/tftp.pcap", pk)
# Length-prefixed TCP (u32le total length including header), JSON bodies, two messages per segment at times
pk = []
seq = 1
msgs = []
for i in range(60):
    body = ('{"op":"%s","id":%d,"x":%d}' % (rng.choice(["move", "say", "buy"]), i, rng.randrange(1000))).encode()
    msgs.append(struct.pack("<IH", 6 + len(body), rng.choice([1, 2, 3])) + body)
i = 0
while i < len(msgs):
    chunk = b"".join(msgs[i:i + rng.choice([1, 1, 2])]); n = len(msgs[i:i + 2]) if len(chunk) > len(msgs[i]) else 1
    pk.append(at(Ether()/IP(src="10.0.3.2", dst="10.0.3.3")/TCP(sport=45000, dport=9000, seq=seq, flags="PA")/Raw(chunk), t)); seq += len(chunk); t += 0.01; i += n
wrpcap(f"{out}/lenprefix.pcap", pk)
# Line protocol
pk = []
seq = 1
for i in range(40):
    line = rng.choice([b"PING %d\r\n" % i, b"SAY hello world\r\n", b"MOVE %d %d\r\n" % (rng.randrange(99), rng.randrange(99))])
    pk.append(at(Ether()/IP(src="10.0.4.2", dst="10.0.4.3")/TCP(sport=46000, dport=6667, seq=seq, flags="PA")/Raw(line), t)); seq += len(line); t += 0.01
wrpcap(f"{out}/lines.pcap", pk)

# Game protocol: magic, type, per-client sequence, payload length, CRC-32, time
rng = random.Random(7)
pkts = []
t0 = 1760000000.0
seq = {1: 100, 2: 5000}
for i in range(240):
    client = 1 + (i % 2)
    kind = rng.choice([1, 1, 2, 3])
    if kind == 1:
        payload = struct.pack("<fffB", rng.uniform(-500, 500), rng.uniform(0, 64), rng.uniform(-500, 500), rng.randint(0, 3))
    elif kind == 2:
        payload = rng.choice([b"hello there", b"gg", b"anyone want to trade?", b"lag!!"]) 
    else:
        payload = struct.pack("<Q", rng.getrandbits(64))
    seq[client] += 1
    t = t0 + i * 0.05
    header = b"GAME" + struct.pack("<BIHII", kind, seq[client], len(payload), zlib.crc32(payload), int(t))
    p = Ether()/IP(src=f"10.0.0.{client}", dst="10.0.0.9")/UDP(sport=40000 + client, dport=7777)/Raw(header + payload)
    p.time = t
    pkts.append(p)
wrpcap(f"{out}/game.pcap", pkts)
`;
