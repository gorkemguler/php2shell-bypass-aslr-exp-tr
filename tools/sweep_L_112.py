#!/usr/bin/env python3
import subprocess,time,re
def sh(c,timeout=60): return subprocess.run(c,shell=True,cwd='/home/debian/php-lab',capture_output=True,text=True,timeout=timeout)
def restart():
    sh("sudo -n apache2ctl -k stop >/dev/null 2>&1"); time.sleep(0.22)
    sh('sudo -n bash -c "setarch $(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1'); time.sleep(0.3)
def child():
    out=sh('pgrep -f "^/usr/sbin/apache2 -k start"').stdout.split()
    return out[-1] if len(out)>=2 else None
for L in range(1000,1101,8):
    restart()
    w=child()
    if not w: print(f"L={L} nochild"); continue
    log=f"/tmp/L_{L}.log"; sh(f"rm -f {log}")
    sh(f"(sudo -n gdb -q -p {w} -batch -x mem2.gdb >{log} 2>&1 &) ; sleep 0.4")
    sh(f"python3 send_a_names.py 128 3000 {L} >/dev/null 2>&1",40)
    time.sleep(0.5)
    sh(f"sudo -n pkill -f 'gdb -q -p {w}' >/dev/null 2>&1")
    lines=sh(f"grep RESET {log}").stdout.strip().splitlines()
    first=lines[0] if lines else "NO_RESET"
    # post state (largest pid)
    c=child(); post="nochild"
    if c:
        out=sh(f"sudo -n gdb -q -p {c} -batch -ex 'p/x (unsigned long)ps_globals.id' -ex 'p ps_globals.send_cookie' 2>/dev/null").stdout
        m=re.search(r'\$1 = (0x[0-9a-f]+)',out); s=re.search(r'\$2 = (true|false)',out)
        post=f"id={m.group(1) if m else '?'} send={s.group(1) if s else '?'}"
    print(f"L={L} {first[:110]} POST {post}",flush=True)
