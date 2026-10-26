set pagination off
set confirm off
break php_session_reset_id
commands
silent
set $h = ((zend_mm_chunk*)0x7ffff5e00000)->heap
printf "RESET id=%p send=%d real=%lu limit=%lu slot11=%p chunks=%d\n", ps_globals.id, ps_globals.send_cookie, $h->real_size, $h->limit, $h->free_slot[11], $h->chunks_count
if ps_globals.id
  printf "IDLEN=%lu IDDATA=", ((zend_string*)ps_globals.id)->len
  x/4gx (char*)ps_globals.id
end
set $c = $h->main_chunk
set $i = 0
while $c != 0
  printf "CHUNK %d addr=%p free_pages=%u\n", $i, $c, $c->free_pages
  set $i = $i + 1
  set $c = $c->next
  if $c == $h->main_chunk
    set $c = 0
  end
end
continue
end
continue
