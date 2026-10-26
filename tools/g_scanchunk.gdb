set pagination off
set confirm off
set logging file /tmp/g_scan.log
set logging overwrite on
set logging enabled on
python
import gdb, struct
def scan_chunk():
    inf=gdb.selected_inferior()
    base=0x7ffff5e00000
    mem=inf.read_memory(base,0x200000).tobytes()
    libphp=(0x7ffff4400000,0x7ffff4b00000)
    libc=(0x7ffff7cc8000,0x7ffff8000000)
    import collections
    ph=collections.Counter(); pc=collections.Counter()
    for off in range(0,len(mem)-8,8):
        v=int.from_bytes(mem[off:off+8],'little')
        if libphp[0]<=v<libphp[1]: ph[(off>>12)<<12]+=1
        elif libc[0]<=v<libc[1]: pc[(off>>12)<<12]+=1
    print("LIBPHP_PAGES", " ".join("%x:%d"%(k,v) for k,v in sorted(ph.items())[:80]))
    print("LIBC_PAGES", " ".join("%x:%d"%(k,v) for k,v in sorted(pc.items())[:80]))
end
break php_session_send_cookie
commands
silent
printf "SEND id=%p\n", ps_globals.id
python scan_chunk()
continue
end
continue
