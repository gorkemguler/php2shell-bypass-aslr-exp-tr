set pagination off
set confirm off
set logging file /tmp/g_dump.log
set logging overwrite on
set logging enabled on
break php_session_send_cookie
commands
silent
printf "SEND id=%p\n", ps_globals.id
dump binary memory /tmp/chunk.bin 0x7ffff5e00000 0x7ffff6000000
python
import gdb
inf=gdb.selected_inferior()
try:
    print("PID", inf.pid)
    open('/tmp/chunk.maps','w').write(open('/proc/%d/maps'%inf.pid).read())
except Exception as e: print("MAPERR",e)
end
continue
end
continue
