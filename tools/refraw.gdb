set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/main/rfc1867.c:887 if new_val_len == 55
commands
silent
printf "REFRAW value=%p len=%lu param=%s\n", value, (unsigned long)new_val_len, param
continue
end
continue
