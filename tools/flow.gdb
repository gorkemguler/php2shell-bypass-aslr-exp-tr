set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP enter id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
continue
end
break php_session_initialize
commands
silent
printf "INIT enter id=%p send=%d status=%d\n", ps_globals.id, ps_globals.send_cookie, ps_globals.session_status
continue
end
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:481
commands
silent
printf "TRACKCALL id=%p type=%x\n", ps_globals.id, ps_globals.http_session_vars.u1.type_info
continue
end
continue
