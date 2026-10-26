set pagination off
set confirm off
set logging file /tmp/g_oom.log
set logging overwrite on
set logging enabled on
break php_session_send_cookie
commands
silent
printf "SEND_COOKIE id=%p len=%ld size=%zu real=%zu peak=%zu limit=%zu\n", ps_globals.id, *((long*)ps_globals.id+2), ((zend_mm_heap*)0x7ffff5e00040)->size, ((zend_mm_heap*)0x7ffff5e00040)->real_size, ((zend_mm_heap*)0x7ffff5e00040)->peak, ((zend_mm_heap*)0x7ffff5e00040)->limit
continue
end
break zend_mm_safe_error
commands
silent
printf "MM_SAFE_ERROR size=%zu size_field=%zu real=%zu limit=%zu\n", size, heap->size, heap->real_size, heap->limit
bt 4
continue
end
continue
