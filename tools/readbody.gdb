set pagination off
set confirm off
break multipart_buffer_read_body
commands
silent
finish
printf "READBODY ret=%p first=%lx\n", $rax, *(unsigned long*)$rax
continue
end
continue
