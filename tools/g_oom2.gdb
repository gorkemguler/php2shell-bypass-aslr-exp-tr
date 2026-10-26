set pagination off
set confirm off
set logging file /tmp/g_oom.log
set logging overwrite on
set logging enabled on
break php_session_send_cookie
commands
silent
printf "SEND_COOKIE id=%p len=%ld\n", ps_globals.id, *((long*)ps_globals.id+2)
continue
end
break zend_mm_safe_error
commands
silent
printf "MM_SAFE_ERROR size=%zu\n", size
printf "HEAP size=%zu peak=%zu limit=%zu\n", heap->size, heap->peak, heap->limit
bt 8
continue
end
continue
