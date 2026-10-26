set pagination off
set confirm off
break php_sapi_filter
commands
silent
printf "FILTER var=%s len=%lu raw=%p\n", (char*)$rsi, $rcx, *(void**)$rdx
continue
end
continue
