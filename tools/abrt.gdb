set pagination off
set confirm off
handle SIGABRT stop print
continue
printf "CAUGHT SIGABRT\n"
bt 20
info registers rip rdi rsi rdx
x/8i $rip-16
