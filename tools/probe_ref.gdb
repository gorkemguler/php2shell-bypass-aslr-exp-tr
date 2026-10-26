set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/ext/session/session.c:482
commands
silent
printf "R0 id=%p ref=%p\n", ps_globals.id, ps_globals.http_session_vars.value.ref
continue
end
break zend_reference_destroy
commands
silent
printf "DESTROY ref=%p gc=%lx val=%p type=%x sources=%p\n", ref, *(unsigned long*)ref, ((zend_reference*)ref)->val.value, ((zend_reference*)ref)->val.u1.type_info, ((zend_reference*)ref)->sources
continue
end
continue
