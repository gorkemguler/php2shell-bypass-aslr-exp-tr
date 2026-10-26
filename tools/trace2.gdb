set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d status=%d\n", ps_globals.id, ps_globals.send_cookie, ps_globals.session_status
if ps_globals.id
x/8gx ps_globals.id
end
continue
end
break php_rshutdown_session_globals
commands
silent
printf "RSHUT id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
if ps_globals.id
x/8gx ps_globals.id
end
continue
end
continue
