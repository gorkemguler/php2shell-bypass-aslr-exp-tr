set pagination off
set confirm off
break php_session_send_cookie
commands
silent
printf "COOKIE enter send=%d slot11=%p\n", ps_globals.send_cookie, ((zend_mm_chunk*)0x7ffff5e00000)->heap->free_slot[11]
continue
end
break zend_mm_safe_error
commands
silent
printf "OOM limit=%lu size=%lu alloc=%lu fmt=%s\n", ((zend_mm_heap*)$rdi)->limit, ((zend_mm_heap*)$rdi)->size, $rcx, (char*)$rsi
bt 12
detach
quit
end
continue
