set pagination off
set confirm off
break php_session_reset_id
commands
silent
set $h = ((zend_mm_chunk*)0x7ffff5e00000)->heap
set $c = $h->main_chunk
set $i = 0
printf "RESET send=%d size=%lu real=%lu limit=%lu slot11=%p chunks=%d\n", ps_globals.send_cookie, $h->size, $h->real_size, $h->limit, $h->free_slot[11], $h->chunks_count
while $i < 8
  printf "CHUNK %d addr=%p free_pages=%u free_tail=%u\n", $i, $c, $c->free_pages, $c->free_tail
  set $c = $c->next
  set $i = $i + 1
  if $c == $h->main_chunk
    loop_break
  end
end
continue
end
continue
