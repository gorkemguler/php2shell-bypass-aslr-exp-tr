set pagination off
set confirm off
break php_session_track_init
commands
silent
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  printf "TRACKIN id=%p ref=%p gc=%lx val=%p type=%x sources=%p\n", ps_globals.id, $r, *(unsigned long*)$r, ((zend_reference*)$r)->val.value, ((zend_reference*)$r)->val.u1.type_info, ((zend_reference*)$r)->sources
else
  printf "TRACKIN id=%p UNDEF type=%x\n", ps_globals.id, ps_globals.http_session_vars.u1.type_info
end
continue
end
continue
