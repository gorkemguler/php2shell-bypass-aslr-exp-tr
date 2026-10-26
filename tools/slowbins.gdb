set pagination off
set confirm off
set $chunk0 = (zend_mm_chunk*)0x7ffff5e00000
break zend_mm_alloc_small_slow
commands
silent
printf "SLOW bin=%u map6e=0x%x\n", $esi, $chunk0->map[0x6e]
bt 6
continue
end
continue
