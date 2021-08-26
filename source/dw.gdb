start

call (void *) dlopen("/home/davidpiche/Documents/exp-setup-mem/pn-test/libdw.so",2)
call (void) dw_init()
source /home/davidpiche/Documents/exp-setup-mem/pn-test/sigill-handler.py
source /home/davidpiche/Documents/exp-setup-mem/pn-test/datawatch-segfault.py
source /home/davidpiche/Documents/exp-setup-mem/pn-test/syscall-handler.py

handle SIGSEGV ignore
catch signal SIGSEGV
commands
silent
set scheduler-locking on
dataWatch-segfault
end

handle SIGBUS ignore
catch signal SIGBUS
commands
silent
dataWatch-segfault
end

tbreak exit
commands
#tbreak *(&final_check)
#compile final_check()
p $rsp=$rsp-8
p *(uint64_t *)$rsp = $pc
jump *(&final_check)
end
#layout regs
#b*0x555556347419
c
