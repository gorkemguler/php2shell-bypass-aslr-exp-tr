set pagination off
set confirm off
break php_session_rfc1867_cleanup
commands
silent
printf "CLEANUP id=%p send=%d\n", ps_globals.id, ps_globals.send_cookie
if ps_globals.id
  x/6gx ps_globals.id
end
continue
end
break php_session_send_cookie
commands
silent
printf "SENDCOOKIE id=%p len=%lu\n", ps_globals.id, ((zend_string*)ps_globals.id)->len
continue
end
continue
