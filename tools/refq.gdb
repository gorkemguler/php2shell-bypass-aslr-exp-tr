set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:481
commands
silent
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  printf "REF r=%p q0=%lx q1=%lx q2=%lx q3=%lx\n", $r, *(unsigned long*)$r, *((unsigned long*)$r+1), *((unsigned long*)$r+2), *((unsigned long*)$r+3)
  detach
  quit
end
continue
end
continue
