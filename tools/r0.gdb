set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:482
commands
silent
printf "TRACK id=%p type=%x ref=%p\n", ps_globals.id, ps_globals.http_session_vars.u1.type_info, ps_globals.http_session_vars.value.ref
continue
end
continue
