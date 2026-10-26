set pagination off
set confirm off
break php_session_reset_id
commands
silent
set $h = ((zend_mm_chunk*)0x7ffff5e00000)->heap
set $c = $h->main_chunk
set $i = 0
printf "RESET send=%d real=%lu limit=%lu slot4=%p slot11=%p chunks=%d\n", ps_globals.send_cookie, $h->real_size, $h->limit, $h->free_slot[4], $h->free_slot[11], $h->chunks_count
while $c != 0
  printf "CH %d free=%u\n", $i, $c->free_pages
  set $i = $i + 1
  set $c = $c->next
  if $c == $h->main_chunk
    set $c = 0
  end
end
continue
end
continue
