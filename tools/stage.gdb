set pagination off
set confirm off
set $chunk0 = (zend_mm_chunk*)0x7ffff5e00000
break php_hash_environment
commands
silent
printf "HASHENV map6e=0x%x map6f=0x%x\n", $chunk0->map[0x6e], $chunk0->map[0x6f]
continue
end
break zend_activate_modules
commands
silent
printf "ACTMOD map6e=0x%x map6f=0x%x\n", $chunk0->map[0x6e], $chunk0->map[0x6f]
continue
end
break php_session_rfc1867_callback
commands
silent
printf "CB event=%d map6e=0x%x map6f=0x%x\n", $edi, $chunk0->map[0x6e], $chunk0->map[0x6f]
continue
end
break php_sapi_filter
commands
silent
printf "FILTER var=%s len=%lu raw=%p map6e=0x%x map6f=0x%x\n", (char*)$rsi, $rcx, *(void**)$rdx, $chunk0->map[0x6e], $chunk0->map[0x6f]
continue
end
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d map6e=0x%x map6f=0x%x\n", ps_globals.id, ps_globals.send_cookie, $chunk0->map[0x6e], $chunk0->map[0x6f]
continue
end
continue
