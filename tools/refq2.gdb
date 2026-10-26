set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:481
commands
silent
printf "HIT id=%p type=%x", ps_globals.id, ps_globals.http_session_vars.u1.type_info
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  printf " ref=%p q0=%lx q1=%lx q2=%lx q3=%lx", $r, *(unsigned long*)$r, *((unsigned long*)$r+1), *((unsigned long*)$r+2), *((unsigned long*)$r+3)
end
printf "\n"
continue
end
continue
