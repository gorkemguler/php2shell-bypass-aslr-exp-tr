set pagination off
set confirm off
set logging file /tmp/g_dump2.log
set logging overwrite on
set logging enabled on
break php_session_track_init
commands
silent
printf "TRACK\n"
printf "PSID=%p PSVARS=%p ti=%x\n", ps_globals.id, ps_globals.http_session_vars.value.ptr, ps_globals.http_session_vars.u1.type_info
dump binary memory /tmp/chunk2.bin 0x7ffff3c00000 0x7ffff3e00000
printf "IDPAGE\n"
x/8gx 0x7ffff3c7d000
python
import gdb
inf=gdb.selected_inferior()
try:
    open('/tmp/chunk2.maps','w').write(open('/proc/%d/maps'%inf.pid).read())
except Exception as e: print("MAPERR",e)
end
continue
end
break zend_reference_destroy
commands
silent
printf "REF_DESTROY %p\n", $rdi
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
