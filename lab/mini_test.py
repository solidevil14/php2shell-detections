#!/usr/bin/env python3
"""Bisection tests for rule misses."""
import os, sys, json, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_build import write_pcap

SIP, PORT = "198.51.100.10", 80

def req(body=b"", headers=None, path="/index.php"):
    h = f"POST {path} HTTP/1.1\r\nHost: t\r\n"
    for k, v in (headers or {}).items():
        h += f"{k}: {v}\r\n"
    return (h + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body

def resp(status="200 OK", headers="", body=b""):
    return (f"HTTP/1.1 {status}\r\nServer: Apache\r\n{headers}"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body

def leak_cookie(n):
    raw = (bytes(range(256)) * ((n // 256) + 1))[:n]
    raw = raw[:9] + b"\x7f" + raw[10:]
    enc = "".join("%"+("%02X" % b) if (b < 0x21 or b > 0x7E or chr(b) in ";,= ")
                  else chr(b) for b in raw).encode()
    return f"Set-Cookie: PHPSESSID={enc.decode()}; path=/\r\n"

def stream(cport, sreq, sresp):
    return {"cip": "203.0.113.77", "cport": cport, "sip": SIP,
            "sport": PORT, "req": sreq, "resp": sresp}

def memprobe_body(big_mb=None):
    parts = [{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p2smem"}]
    if big_mb:
        parts.append({"name": "big", "data": b"B" * (big_mb * 1024 * 1024)})
    out = b""
    bnd = b"P2SMEMPROBE"
    for p in parts:
        out += b"--" + bnd + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"\r\n\r\n'
        out += p["data"] + b"\r\n"
    out += b"--" + bnd + b"--\r\n"
    return out

plain_oom = ("HTTP fatal: Allowed memory size of 8388608 bytes exhausted "
             "(tried to allocate 1 bytes) in Unknown on line 0").encode()
html_oom = ("<b>Fatal error</b>:  Allowed memory size of 8388608 bytes "
            "exhausted (tried to allocate 1 bytes) in <b>Unknown</b> on "
            "line <b>0</b><br />").encode()

streams = [
    stream(43001, req(memprobe_body(10), {"Content-Type": "multipart/form-data; boundary=P2SMEMPROBE"}),
           resp(body=b"ok")),                                  # T1 full 10MB
    stream(43002, req(memprobe_body(), {"Content-Type": "multipart/form-data; boundary=P2SMEMPROBE"}),
           resp(body=b"ok")),                                  # T2 small
    stream(43003, req(b"x=1"), resp(headers=leak_cookie(1100), body=b"ok")),   # T3 leak 1100
    stream(43004, req(b"x=1"), resp(headers="Set-Cookie: PHPSESSID=abc123; path=/\r\n", body=b"ok")),  # T4 neg
    stream(43005, req(b"x=1"), resp(status="500 Internal Server Error", body=plain_oom)),  # T5 plain
    stream(43006, req(b"x=1"), resp(status="500 Internal Server Error", body=html_oom)),   # T6 html
    stream(43007, req(memprobe_body(2), {"Content-Type": "multipart/form-data; boundary=P2SMEMPROBE"}),
           resp(body=b"ok")),                                  # T7 2MB
]

here = os.path.dirname(os.path.abspath(__file__))
write_pcap(os.path.join(here, "mini.pcap"), streams)
print("mini.pcap written")
