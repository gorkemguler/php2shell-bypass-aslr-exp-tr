#!/bin/bash
# usage: trial_ab.sh F S NB BL X K KL FL
# Fresh worker + gdb attached (breakpoints resolved), then A (OOM-in-cookie)
# and B (packing/forge) on the same worker.
set -u
cd /home/debian/php2shell-work
S() { sudo -n "$@"; }

stop_all() {
  S bash -c "pkill -9 gdb 2>/dev/null; apache2ctl -k stop 2>/dev/null; sleep 0.5; pkill -9 apache2 2>/dev/null" >/dev/null 2>&1
  local i
  for i in $(seq 1 50); do
    [ -z "$(pgrep -x apache2 2>/dev/null)" ] && return 0
    sleep 0.1
  done
  return 1
}

start_worker_http() {
  local i m w st
  if [ "${ASLR_ON:-0}" = "1" ]; then
    S bash -c "/usr/sbin/apache2ctl -k start" >/dev/null 2>&1
  else
    S bash -c "setarch \$(uname -m) -R /usr/sbin/apache2ctl -k start" >/dev/null 2>&1
  fi
  for i in $(seq 1 60); do
    sleep 0.1
    m=$(pgrep -o -x apache2 2>/dev/null); [ -z "$m" ] && continue
    w=$(pgrep -P "$m" -x apache2 2>/dev/null | tail -1); [ -z "$w" ] && continue
    st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8088/ 2>/dev/null)
    if [ "$st" = "200" ]; then echo "$m $w"; return 0; fi
  done
  return 1
}

FRESH=0
for attempt in 1 2 3; do
  stop_all || continue
  S rm -f /tmp/sess_* /tmp/g_bins.log /tmp/gdb_bins.log /tmp/a_oom4.resp /tmp/a_oom4.out /tmp/b_out.txt /tmp/b_open.resp >/dev/null 2>&1
  read -r M W <<< "$(start_worker_http)" || continue
  [ -z "${M:-}" ] && continue
  echo "MASTER=$M WORKER=$W HTTP=200 attempt=$attempt"
  S nohup gdb -p "$W" -batch -x /tmp/g_bins.gdb >/tmp/gdb_bins.log 2>&1 &
  local_i=0
  while [ $local_i -lt 50 ]; do
    sleep 0.1
    local_i=$((local_i+1))
    if S grep -aq "Breakpoint 3 at 0x" /tmp/gdb_bins.log 2>/dev/null; then FRESH=1; break; fi
  done
  [ $FRESH -eq 1 ] && break
  echo "GDB_ATTACH_RETRY"
done
if [ $FRESH -ne 1 ]; then echo "GDB_ATTACH_FAILED"; S pkill -9 gdb >/dev/null 2>&1; exit 1; fi

timeout 90 python3 send_a_oom5.py "$@" >/tmp/a_oom4.out 2>&1
sleep 0.5
W2=$(pgrep -P "$M" -x apache2 | tail -1)
echo "WORKER_AFTER_A=$W2"
timeout 60 python3 send_b_open.py "${BN:-900}" "${BVL:-231}" >/tmp/b_out.txt 2>&1
sleep 0.5
S pkill -9 gdb >/dev/null 2>&1
echo "---- A OUT"
cat /tmp/a_oom4.out
echo "---- B OUT"
cat /tmp/b_out.txt
echo "---- GDB"
S grep -aE "SESSION_INIT|SEND_COOKIE|MM_SAFE_ERROR|PS_AT_OOM|OPEN_FILES|RESET_ID|RSHUT_ID|ZEND_MM_PANIC|ABORT_CALLED|^#[0-9]|Breakpoint" /tmp/gdb_bins.log | head -60
