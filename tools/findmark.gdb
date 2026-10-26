set pagination off
set confirm off
break php_session_track_init
commands
silent
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  printf "TRACKIN id=%p ref=%p gc=%lx\n", ps_globals.id, $r, *(unsigned long*)$r
  find /g 0x7ffff5e00000, 0x7ffff6000000, $mark
  detach
  quit
end
continue
end
continue
