set pagination off
set confirm off
break php_session_track_init
commands
silent
if (ps_globals.http_session_vars.u1.type_info & 0xff) == 10
  set $r = ps_globals.http_session_vars.value.ref
  set $chunk = (zend_mm_chunk*)0x7ffff5e00000
  set $page = ((unsigned long)$r & 0x1fffff) >> 12
  printf "TRACKIN ref=%p page=%d map=0x%x\n", $r, $page, $chunk->map[$page]
  printf "FREESLOT6=%p FREESLOT3=%p\n", $chunk->heap->free_slot[6], $chunk->heap->free_slot[3]
  detach
  quit
end
continue
end
continue
