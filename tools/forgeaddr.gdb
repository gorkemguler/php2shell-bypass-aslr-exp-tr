set pagination off
set confirm off
break php_sapi_filter if val_len == 31
commands
silent
printf "FORGE raw=%p var=%s len=%lu\n", *val, var, val_len
continue
end
continue
