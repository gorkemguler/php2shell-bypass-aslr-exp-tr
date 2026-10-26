set pagination off
set confirm off
set logging file /tmp/g_cookie.log
set logging overwrite on
set logging enabled on
break php_session_send_cookie
commands
silent
printf "SEND_COOKIE id=%p send_cookie=%d hs=%d\n", ps_globals.id, ps_globals.send_cookie, sapi_globals.headers_sent
printf "IDHDR\n"
x/8gx ps_globals.id
printf "PREV\n"
x/8gx ps_globals.id-0x40
continue
end
break php_url_encode
commands
silent
printf "URL_ENCODE len=%ld str=%p\n", $rsi, $rdi
continue
end
continue
