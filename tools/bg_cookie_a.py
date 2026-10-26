#!/usr/bin/env python3
import socket
HOST='127.0.0.1'; PORT=8088; SID='bgtest123'
h=(f'GET /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nCookie: PHPSESSID={SID}\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=30); s.settimeout(30)
try: s.sendall(h)
except OSError as e: print('send err',e)
d=b''
try:
    while True:
        c=s.recv(65536)
        if not c: break
        d+=c
except OSError as e: print('recv err',e)
s.close()
print(d[:300].decode('latin1','replace'))
