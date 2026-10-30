#!/usr/bin/env python3
"""pcap_build.py - minimal pure-python pcap writer (Ethernet/IPv4/TCP).

Builds a pcap from a list of streams (wire-exact, checksums correct):
    {"cip":..,"cport":..,"sip":..,"sport":..,"req":bytes,"resp":bytes}
Each stream gets a full TCP handshake + data exchange + FIN teardown,
with correct IPv4/TCP checksums so Suricata's stream engine accepts it.
"""
import struct

ETH = bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + b"\x08\x00"
MSS = 1400

def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def _ip(src: str, dst: str, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                      0x4000, 64, 6, 0,
                      bytes(map(int, src.split("."))),
                      bytes(map(int, dst.split("."))))
    c = _cksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload

def _tcp(sp: int, dp: int, seq: int, ack: int, flags: int,
         payload: bytes = b"", src: str = "", dst: str = "") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      0x50, flags, 64240, 0, 0)
    pseudo = (bytes(map(int, src.split("."))) + bytes(map(int, dst.split(".")))
              + struct.pack("!BBH", 0, 6, len(hdr) + len(payload)))
    c = _cksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    return hdr + payload

def stream_packets(s: dict, ts0: float):
    cip, sip = s["cip"], s["sip"]
    cport, sport = s["cport"], s["sport"]
    req, resp = s["req"], s["resp"]
    seq_c, seq_s = 1000, 2000
    ident = 1
    out = []

    def emit(t, w, p):
        nonlocal ident
        out.append((t, ETH + _ip(w[0], w[1], p, ident & 0xFFFF)))
        ident += 1

    def tcp(w, seq, ack, flags, payload=b""):
        return _tcp(w[2], w[3], seq, ack, flags, payload, w[0], w[1])

    C = (cip, sip, cport, sport)
    S = (sip, cip, sport, cport)

    emit(ts0, C, tcp(C, seq_c, 0, 0x02))                      # SYN
    emit(ts0 + 0.001, S, tcp(S, seq_s, seq_c + 1, 0x12))      # SYN-ACK
    seq_c += 1
    emit(ts0 + 0.002, C, tcp(C, seq_c, seq_s + 1, 0x10))      # ACK
    seq_s += 1

    t = ts0 + 0.003
    for chunk in (req[i:i + MSS] for i in range(0, len(req), MSS)):
        emit(t, C, tcp(C, seq_c, seq_s, 0x18, chunk))          # PSH,ACK
        seq_c += len(chunk)
        emit(t + 0.0002, S, tcp(S, seq_s, seq_c, 0x10))
        t += 0.001

    for chunk in (resp[i:i + MSS] for i in range(0, len(resp), MSS)):
        emit(t, S, tcp(S, seq_s, seq_c, 0x18, chunk))
        seq_s += len(chunk)
        emit(t + 0.0002, C, tcp(C, seq_c, seq_s, 0x10))
        t += 0.001

    emit(t + 0.001, C, tcp(C, seq_c, seq_s, 0x11))             # FIN,ACK
    seq_c += 1
    emit(t + 0.002, S, tcp(S, seq_s, seq_c, 0x11))
    seq_s += 1
    emit(t + 0.003, C, tcp(C, seq_c, seq_s, 0x10))
    return out

def write_pcap(path: str, streams: list):
    pkts = []
    ts = 1727300000.0
    for s in streams:
        pkts.extend(stream_packets(s, ts))
        ts += 1.0  # 1s between streams (xbits expire window still applies)
    pkts.sort(key=lambda x: x[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        prev = 0.0
        for t, frame in pkts:
            dt = max(0, int((t - prev) * 1_000_000))
            cur = prev + dt / 1_000_000
            f.write(struct.pack("<IIII", int(cur), int(cur % 1) * 1_000_000,
                                len(frame), len(frame)))
            f.write(frame)
            prev = cur
    return len(pkts)
