set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
continue
end
break php_sapi_filter
commands
silent
printf "FILTER var=%s len=%lu raw=%p\n", (char*)$rsi, $rcx, *(void**)$rdx
continue
end
continue
