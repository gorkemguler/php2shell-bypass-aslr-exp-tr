set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/g_cal.log
set logging overwrite on
set logging enabled on
break php_session_track_init
commands
silent
printf "TRACK_INIT\n"
printf "PSID=%p\n", ps_globals.id
printf "PSVARS ti=%x ptr=%p\n", ps_globals.http_session_vars.u1.type_info, ps_globals.http_session_vars.value.ptr
if (ps_globals.http_session_vars.u1.type_info & 255) == 10
  set $r = ps_globals.http_session_vars.value.ptr
  printf "REF %p gc=%lx valptr=%p valti=%lx\n", $r, *(unsigned long*)$r, *((void**)$r+1), *((unsigned long*)$r+2)
  printf "R0m10 %p\n", (void*)($r-0x10)
end
printf "FIND_M1\n"
find /g 0x7ffff5e00000, 0x7ffff6000000, 0x1122334455667788
printf "FIND_M2\n"
find /g 0x7ffff5e00000, 0x7ffff6000000, 0xdeadbeefcafebabe
printf "FIND_DONE\n"
continue
end
break zend_reference_destroy
commands
silent
printf "REF_DESTROY ref=%p\n", $rdi
continue
end
break zend_array_destroy
commands
silent
printf "ARR_DESTROY %p\n", $rdi
continue
end
break zend_hash_destroy
commands
silent
printf "HASH_DESTROY %p\n", $rdi
continue
end
continue
