set pagination off
set confirm off
set logging file /tmp/g_zif.log
set logging overwrite on
set logging enabled on
break php_session_track_init
commands
silent
printf "TRACK\n"
printf "PSVARS ti=%x ptr=%p\n", ps_globals.http_session_vars.u1.type_info, ps_globals.http_session_vars.value.ptr
continue
end
break zend_reference_destroy
commands
silent
printf "REF_DESTROY ref=%p gc=%lx val=%p ti=%lx\n", $rdi, *(unsigned long*)$rdi, *((void**)$rdi+1), *((unsigned long*)$rdi+2)
continue
end
break zend_array_destroy
commands
silent
printf "ARR_DESTROY %p gc=%lx\n", $rdi, *(unsigned long*)$rdi
continue
end
break zend_hash_destroy
commands
silent
printf "HASH_DESTROY %p pd=%p\n", $rdi, *(void**)($rdi+0x30)
continue
end
break zif_system
commands
silent
printf "ZIF_SYSTEM rdi=%p rsi=%p\n", $rdi, $rsi
printf "ED\n"
x/14gx $rdi
continue
end
break __libc_system
commands
silent
printf "LIBC_SYSTEM %s\n", $rdi
continue
end
break popen
commands
silent
printf "POPEN cmd=%s mode=%s\n", $rdi, $rsi
continue
end
continue
