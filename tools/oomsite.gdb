set pagination off
set confirm off
break zend_error
commands
silent
printf "ZEND_ERROR type=%d fmt=%s\n", $rdi, (char*)$rsi
bt 12
detach
quit
end
continue
