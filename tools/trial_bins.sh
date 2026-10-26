#!/bin/bash
# usage: trial_bins.sh F NB BL K KL FL [FN]
set -u
cd /home/debian/php2shell-work
S() { sudo -n "$@"; }
restart() {
  S bash -c "pkill -9 gdb 2>/dev/null; apache2ctl -k stop 2>/dev/null; sleep 0.4; pkill -9 apache2 2>/dev/null; sleep 0.4; setarch \$(uname -m) -R /usr/sbin/apache2ctl -k start; sleep 0.7" >/dev/null 2>&1
}
restart
S rm -f /tmp/sess_* /tmp/g_bins.log /tmp/gdb_bins.log /tmp/a_oom4.resp /tmp/a_oom4.out >/dev/null 2>&1
M=$(pgrep -o -x apache2); W=$(pgrep -P "$M" -x apache2 | tail -1)
echo "MASTER=$M WORKER=$W"
S nohup gdb -p "$W" -batch -x /tmp/g_bins.gdb >/tmp/gdb_bins.log 2>&1 &
sleep 4
timeout 90 python3 send_a_oom5.py "$@" >/tmp/a_oom4.out 2>&1
sleep 1
S pkill -9 gdb >/dev/null 2>&1
echo "---- A OUT"
cat /tmp/a_oom4.out
echo "---- GDB"
S grep -aE "SEND_COOKIE|MM_SAFE_ERROR|^#[0-9]|Breakpoint" /tmp/gdb_bins.log | head -40
