set pagination off
set confirm off
set logging file /tmp/g_cookie.log
set logging overwrite on
set logging enabled on
python
import gdb, struct
def _regions():
    inf=gdb.selected_inferior()
    for line in open('/proc/%d/maps'%inf.pid):
        p=line.split()
        if len(p)<2 or p[1]!='rw-p': continue
        if len(p)>5 and p[5].startswith('/'): continue
        a,b=[int(x,16) for x in p[0].split('-')]
        if b-a>0x2000000 or b-a<0x1000: continue
        try: yield a, inf.read_memory(a,b-a).tobytes()
        except Exception: continue
def scanq(v):
    pat=struct.pack('<Q',v); out=[]
    for a,mem in _regions():
        off=0
        while True:
            i=mem.find(pat,off)
            if i<0: break
            out.append(a+i); off=i+1
    print("SCANQ %d N=%d %s"%(v,len(out)," ".join(hex(x) for x in out[:40])))
end
break php_session_send_cookie
commands
silent
printf "SEND id=%p send_cookie=%d hs=%d\n", ps_globals.id, ps_globals.send_cookie, sapi_globals.headers_sent
printf "IDPAGE\n"
x/8gx 0x7ffff5ea9000
python scanq(1234)
python scanq(1500)
continue
end
continue
