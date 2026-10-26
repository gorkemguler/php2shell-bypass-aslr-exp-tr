set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p\n", ps_globals.id
set $zv = (zval*)&PG(http_globals)[0]
printf "POST zval type_info=0x%x arr=%p\n", $zv->u1.type_info, $zv->value.arr
set $ht = $zv->value.arr
if $ht != 0
  printf "HT addr=%p pDestructor=%p arData=%p nNumUsed=%u nTableSize=%u\n", $ht, $ht->pDestructor, $ht->arData, $ht->nNumUsed, $ht->nTableSize
end
detach
quit
end
continue
