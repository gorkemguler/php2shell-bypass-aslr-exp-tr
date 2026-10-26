set pagination off
set confirm off
break php_session_reset_id
commands
silent
set $h = ((zend_mm_chunk*)0x7ffff5e00000)->heap
printf "RESET send=%d size=%lu limit=%lu free=%ld peak=%lu\n", ps_globals.send_cookie, $h->size, $h->limit, (long)($h->limit - $h->size), $h->peak
continue
end
continue
