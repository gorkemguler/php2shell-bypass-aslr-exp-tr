set pagination off
set confirm off
set breakpoint pending on
break php_session_initialize
commands
silent
printf "INIT BEFORE id=%p send=%d status=%d headers=%d\n", ps_globals.id, ps_globals.send_cookie, ps_globals.session_status, sapi_globals.headers_sent
continue
end
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP ENTER id=%p send=%d status=%d headers=%d\n", ps_globals.id, ps_globals.send_cookie, ps_globals.session_status, sapi_globals.headers_sent
continue
end
break php_session_reset_id
commands
silent
printf "RESET_ID id=%p send=%d headers=%d\n", ps_globals.id, ps_globals.send_cookie, sapi_globals.headers_sent
continue
end
continue
