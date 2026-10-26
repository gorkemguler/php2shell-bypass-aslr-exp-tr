set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
set $chunk0 = (zend_mm_chunk*)0x7ffff5e00000
printf "CLEANUP id=%p send=%d map6e=0x%x\n", ps_globals.id, ps_globals.send_cookie, $chunk0->map[0x6e]
x/8gx ps_globals.id
detach
quit
end
continue
