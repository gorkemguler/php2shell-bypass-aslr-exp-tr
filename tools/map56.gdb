set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p\n", ps_globals.id
set $chunk = (zend_mm_chunk*)0x7ffff5e00000
set $i = 1
while $i < 512
  set $info = $chunk->map[$i]
  if ($info & 0x80000000) != 0
    set $bin = $info & 0x1f
    if $bin == 6
      printf "PAGE56 %d addr=0x%lx info=0x%x\n", $i, (unsigned long)$chunk + $i*4096, $info
    end
  end
  set $i = $i + 1
end
if ps_globals.id
printf "SLOT0:\n"
x/12gx ps_globals.id
end
detach
quit
end
continue
