#!/usr/bin/env python3
"""mock_target.py - behavioral replica of a vulnerable PHP 8.4.26
mod_php+prefork target, for running the real php2shell CLI against it.

Serves the exact wire behaviors the toolkit parses:
  * no version disclosure (X-Powered-By omitted)  -> detect verdict unknown
    -> oomprobe auto-probes (nested-62 1/8/20 MiB) hit the wire
  * "Allowed memory size of 8388608 bytes exhausted ... in Unknown on line 0"
    -> memory_limit parsing + the OOM-in-parser S1 signal
  * forged heap-leak Set-Cookie payloads:
      - chunk-base flood (>=8 x 0x7F2B04000000 in >=1000 bytes)  -> stage1
      - pDestructor pointer at raw[8:16]                          -> stage2
  * GET /out/p1 -> uid=33(www-data)  (proof channel for --fetch)

Stateless classification by body content, mirroring how lib/chain.py sends
its requests.
"""
import socket
import struct
import threading
import urllib.parse

MOCK_PORT = 8096
BASE = 0x7F2B04000000          # forged Zend MM chunk base (2MB aligned)
DTOR = 0x65EB60                # bookworm zval_ptr_dtor offset (PROFILES)
FATAL_8M = ("Fatal error:  Allowed memory size of 8388608 bytes exhausted "
            "(tried to allocate 133169 bytes) in Unknown on line 0").encode()

def http_reply(status, headers=b"", body=b""):  # noqa
    head = (f"HTTP/1.1 {status}\r\nServer: Apache\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n"
            ).encode() + headers + b"\r\n"
    return head + body

def ok_page(extra_headers=b"", body=b"OK\n"):
    return http_reply("200 OK", extra_headers, body)

def fatal_page(status="500 Internal Server Error"):
    body = ("<b>Fatal error</b>:  Allowed memory size of 8388608 bytes "
            "exhausted (tried to allocate 133169 bytes) in "
            "<b>Unknown</b> on line <b>0</b><br />\n").encode()
    return http_reply(status, body=body)

def cookie_hdr(value):
    return ("Set-Cookie: PHPSESSID=%s; path=/\r\n" % value).encode()

def leak_cookie_chunkbase():
    raw = b"".join(struct.pack("<Q", BASE) for _ in range(40))
    raw = raw + b"\x55" * (1040 - len(raw))          # >=1000 bytes
    return cookie_hdr(urllib.parse.quote(raw, safe=""))

def leak_cookie_libphp():
    ptr = BASE + DTOR
    raw = struct.pack("<Q", 4096) + struct.pack("<Q", ptr) + b"\x00" * 16
    return cookie_hdr(urllib.parse.quote(raw, safe=""))

def classify(body: bytes):
    if b"--P2SMEMPROBE" in body:                      # memprobe
        return fatal_page()
    if b"----php2shellprobe" in body:                 # detect UP probe
        return ok_page(cookie_hdr("php2shellprobe0001"))
    if b"a[b][b]" in body[:256]:                      # oomprobe (nested-62)
        # small control returns 200 with body, big probe OOMs in parser
        if len(body) > 4096:
            return fatal_page()
        return ok_page(body=b"control-ok")
    if b'name="g00"' in body or b'Content-Disposition: form-data; name="f00"' in body:
        return ok_page()                              # stage3-final
    if b'name="a0000[' in body:
        return ok_page(leak_cookie_libphp())          # stage2-2nd
    if b'name="v0000"' in body or b'name="1999"' in body:
        return ok_page(leak_cookie_chunkbase())       # stage1-2nd
    if b"BNDRY12345" in body[:256]:                   # rotate-2nd
        return ok_page(body=b"rotated\n")
    if body.startswith(b"--SSSSSSSSSSSSSSSSS") or b"--SSSSSSSSSSSSSSSSS" in body[:4096]:
        if len(body) > 8 * 1024 * 1024:
            return fatal_page()                       # oversize groom? defensible
        return ok_page(body=b"groom-ack\n")
    return ok_page(body=b"ok\n")

def handle(conn):
    try:
        data = b""
        # read headers
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, _rest = data.partition(b"\r\n\r\n")
        cl = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":")[1].strip() or 0)
        body = _rest
        while len(body) < cl:
            chunk = conn.recv(1 << 20)
            if not chunk:
                break
            body += chunk
        if head.upper().startswith(b"GET"):
            path = head.split(b" ")[1]
            if b"/out/p1" in path:
                resp = ok_page(body=b"uid=33(www-data) gid=33(www-data)\n")
            else:
                # version hidden -> detect falls through to OOM probes
                resp = ok_page(body=b"<!doctype html>ok page\n")
        elif cl > 0:
            resp = classify(body)
        else:
            resp = ok_page()
        conn.sendall(resp)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        except OSError:
            pass

def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", MOCK_PORT))
    s.listen(64)
    print(f"[mock] target on 127.0.0.1:{MOCK_PORT}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    try:
        serve()
    except KeyboardInterrupt:
        print("[mock] stopped")
        raise SystemExit(0)
