#!/usr/bin/env python3
"""tee_proxy.py - transparent byte-pump between client and mock_target that
RECORDS every connection's client-request bytes and server-response bytes
into a JSONL file (one line per connection, wire-exact; REC_FILE env or
recorded.jsonl).
"""
import json
import socket
import threading
import time

LISTEN = ("127.0.0.1", 8095)     # where the toolkit points
UPSTREAM = ("127.0.0.1", 8096)   # mock_target
import os
OUT = os.environ.get("REC_FILE", "recorded.jsonl")

sessions = []
lock = threading.Lock()

def pump(src, dst, buf):
    try:
        while True:
            data = src.recv(1 << 20)
            if not data:
                break
            buf.extend(data)
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass

def handle(client):
    try:
        upstream = socket.create_connection(UPSTREAM, timeout=120)
        req, resp = bytearray(), bytearray()
        t1 = threading.Thread(target=pump, args=(client, upstream, req), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, client, resp), daemon=True)
        t1.start(); t2.start()
        t1.join(180); t2.join(180)
        for s in (client, upstream):
            try: s.close()
            except OSError: pass
        rec = {"ts": time.time(),
               "req": bytes(req).decode("latin1"),
               "resp": bytes(resp).decode("latin1")}
        with lock:
            sessions.append(rec)
            with open(OUT, "a") as f:
                f.write(json.dumps(rec) + "\n")
    except OSError:
        pass

def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN); s.listen(128)
    print(f"[tee] recording proxy on {LISTEN[0]}:{LISTEN[1]} -> {OUT}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    open(OUT, "w").close()
    serve()
