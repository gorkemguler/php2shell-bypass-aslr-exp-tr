set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p\n", ps_globals.id
set $chunk = (zend_mm_chunk*)0x7ffff5e00000
set $i = 0
while $i < 512
  set $info = $chunk->map[$i]
  if ($info & 0x80000000) != 0
    set $bin = $info & 0x1f
    if $bin == 7 || $bin == 8
      printf "PAGE %d addr=0x%lx info=0x%x bin=%d\n", $i, (unsigned long)$chunk + $i*4096, $info, $bin
    end
  end
  set $i = $i + 1
end
detach
quit
end
continue
