set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
x/6gx ps_globals.id
continue
end
catch signal SIGABRT
commands
silent
printf "SIGABRT caught\n"
bt 14
quit
end
continue
