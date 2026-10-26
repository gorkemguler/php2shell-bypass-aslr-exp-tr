set pagination off
set confirm off
break zend_mm_safe_error
commands
silent
printf "MM_SAFE_ERROR limit=%lu size=%lu msg=%s\n", ((zend_mm_heap*)$rdi)->limit, ((zend_mm_heap*)$rdi)->size, (char*)$rsi
bt 18
detach
quit
end
continue
