set pagination off
set confirm off
break php_session_reset_id
commands
silent
set $h = ((zend_mm_chunk*)0x7ffff5e00000)->heap
printf "RESET send=%d size=%lu real=%lu limit=%lu rem=%ld slot11=%p mainfree=%u chunks=%d\n", ps_globals.send_cookie, $h->size, $h->real_size, $h->limit, (long)($h->limit - $h->real_size), $h->free_slot[11], $h->main_chunk->free_pages, $h->chunks_count
continue
end
continue
