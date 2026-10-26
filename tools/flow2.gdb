set pagination off
set confirm off
handle SIGABRT nostop noprint pass
handle SIGSEGV nostop noprint pass
handle SIGBUS nostop noprint pass
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
continue
end
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:481
commands
silent
printf "HIT481 id=%p type=%x", ps_globals.id, ps_globals.http_session_vars.u1.type_info
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  printf " ref=%p q0=%lx q1=%lx q2=%lx q3=%lx", $r, *(unsigned long*)$r, *((unsigned long*)$r+1), *((unsigned long*)$r+2), *((unsigned long*)$r+3)
end
printf "\n"
continue
end
continue
