set pagination off
set confirm off
break /home/debian/php-lab/php-8.4.26/main/rfc1867.c:855
commands
silent
printf "VAL value=%p len=%lu first=%lx\n", value, (unsigned long)value_len, *(unsigned long*)value
continue
end
continue
