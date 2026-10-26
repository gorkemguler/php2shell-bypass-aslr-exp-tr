set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
set $chunk3 = (zend_mm_chunk*)0x7ffff3c00000
printf "CLEANUP id=%p send=%d page511=0x%x\n", ps_globals.id, ps_globals.send_cookie, $chunk3->map[511]
detach
quit
end
continue
