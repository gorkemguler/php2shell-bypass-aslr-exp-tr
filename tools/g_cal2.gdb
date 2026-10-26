set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/g_cal.log
set logging overwrite on
set logging enabled on
python
import gdb, struct
def scan(marker, lo=0x7ffff0000000, hi=0x7ffffffff000):
    try:
        inf = gdb.selected_inferior()
    except Exception as e:
        print("SCANERR", e); return
    pat = struct.pack('<Q', marker)
    try:
        maps = open('/proc/%d/maps' % inf.pid).read().splitlines()
    except Exception as e:
        print("SCANERR maps", e); return
    out = []
    for line in maps:
        parts = line.split()
        if len(parts) < 2 or parts[1] != 'rw-p':
            continue
        a, b = [int(x, 16) for x in parts[0].split('-')]
        if b < lo or a > hi:
            continue
        try:
            mem = inf.read_memory(a, b - a).tobytes()
        except Exception:
            continue
        off = 0
        while True:
            i = mem.find(pat, off)
            if i < 0:
                break
            out.append(a + i)
            off = i + 1
    if out:
        print("SCAN %x N=%d %s" % (marker, len(out), " ".join(hex(x) for x in out[:64])))
    else:
        print("SCAN %x N=0" % marker)
end

def dump(marker):
    try:
        inf = gdb.selected_inferior()
        maps = open('/proc/%d/maps' % inf.pid).read().splitlines()
    except Exception as e:
        print("DUMPERR", e); return
    pat = struct.pack('<Q', marker)
    for line in maps:
        parts = line.split()
        if len(parts) < 2 or parts[1] != 'rw-p':
            continue
        a, b = [int(x, 16) for x in parts[0].split('-')]
        if b < 0x7ffff0000000 or a > 0x7ffffffff000:
            continue
        try:
            mem = inf.read_memory(a, b - a).tobytes()
        except Exception:
            continue
        off = 0
        while True:
            i = mem.find(pat, off)
            if i < 0:
                break
            A = a + i
            hs = A - 0x78   # string header if live string
            hr = A - 0x60   # block start if raw buffer
            try:
                sgc = struct.unpack('<Q', inf.read_memory(hs, 8).tobytes())[0]
                slen = struct.unpack('<Q', inf.read_memory(hs + 0x10, 8).tobytes())[0]
                rgc = struct.unpack('<Q', inf.read_memory(hr, 8).tobytes())[0]
                rlen = struct.unpack('<Q', inf.read_memory(hr + 0x10, 8).tobytes())[0]
                print("CAND A=%x str[hdr=%x gc=%x len=%x] raw[blk=%x gc=%x off10=%x]" % (A, hs, sgc, slen, hr, rgc, rlen))
            except Exception as e:
                print("CAND A=%x readerr %s" % (A, e))
            off = i + 1

break php_session_track_init
commands
silent
printf "TRACK_INIT\n"
printf "PSID=%p\n", ps_globals.id
printf "PSVARS ti=%x ptr=%p\n", ps_globals.http_session_vars.u1.type_info, ps_globals.http_session_vars.value.ptr
if (ps_globals.http_session_vars.u1.type_info & 255) == 10
  set $r = ps_globals.http_session_vars.value.ptr
  printf "REF %p gc=%lx valptr=%p valti=%lx\n", $r, *(unsigned long*)$r, *((void**)$r+1), *((unsigned long*)$r+2)
  printf "R0m10 %p\n", (void*)($r-0x10)
end
python scan(0x1122334455667788)
python dump(0x1122334455667788)
python scan(0xdeadbeefcafebabe)
printf "FIND_DONE\n"
continue
end
break zend_reference_destroy
commands
silent
printf "REF_DESTROY ref=%p\n", $rdi
continue
end
break zend_array_destroy
commands
silent
printf "ARR_DESTROY %p\n", $rdi
continue
end
break zend_hash_destroy
commands
silent
printf "HASH_DESTROY %p\n", $rdi
continue
end
continue
