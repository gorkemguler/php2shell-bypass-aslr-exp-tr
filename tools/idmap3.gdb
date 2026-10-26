set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
set $id = ps_globals.id
printf "CLEANUP id=%p send=%d\n", $id, ps_globals.send_cookie
if $id > 0x7ffff5e00000 && $id < 0x7ffff6000000
  set $chunk0 = (zend_mm_chunk*)0x7ffff5e00000
  set $pg = ((unsigned long)$id - 0x7ffff5e00000) >> 12
  printf "page=0x%lx map=0x%x\n", $pg, $chunk0->map[$pg]
end
x/8gx $id
detach
quit
end
continue
